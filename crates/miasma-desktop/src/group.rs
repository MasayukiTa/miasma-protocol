//! Decisions of the group conversations in the Chat area, kept apart from the drawing so they can
//! be tested with fixture data: how groups sit in the conversation list, who a message is from
//! (and whether that person is a contact), what the person may do in a group, what the new-group
//! and add-member forms allow, and the sentence for each state and error.
//!
//! Rules the screens rely on:
//! * being added to a group never makes anyone a contact; a member who is not a contact is shown
//!   as unverified, with a plain label, and nothing about files or permissions follows from it;
//! * there are no read receipts in groups; the only state of a sent message is how many members
//!   it reached;
//! * adding and removing members is for the creator and admins.

use std::collections::{HashMap, HashSet};

use miasma_core::chat::group::engine::MAX_GROUPS;
use miasma_core::chat::group::ipc::{GroupDetailInfo, GroupInfo, GroupMessageInfo, MemberInfo};
use miasma_core::chat::group::membership::{MAX_MEMBERS, MAX_NAME_BYTES};
use miasma_core::config::NodeConfig;
use miasma_core::push::ContactInfo;

use crate::chat::{cap_text, elide, one_line, ListRow, PREVIEW_CHARS};
use crate::locale::{ChatStrings, GroupStrings};
use crate::transfers::fill;

/// Names on one line are cut here (the same length the one-to-one screens use).
pub const NAME_CHARS: usize = 40;
/// Messages asked for at once; the window grows by this much on "Show older messages".
pub const PAGE: u32 = 50;
/// The most the window holds (the service never returns more in one page).
pub const MAX_WINDOW: u32 = 200;
/// Characters of a verification code shown where there is no name.
const CODE_CHARS: usize = 14;

// ─── Groups in the list ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupStatus {
    /// Someone added me; I have not said yes yet.
    Invited,
    Joined,
    Left,
    Removed,
    /// A status this version does not know.
    Other,
}

impl GroupStatus {
    pub fn parse(s: &str) -> Self {
        match s {
            "invited" => Self::Invited,
            "joined" => Self::Joined,
            "left" => Self::Left,
            "removed" => Self::Removed,
            _ => Self::Other,
        }
    }
}

/// One group as the list needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRow {
    pub id: String,
    pub name: String,
    pub status: GroupStatus,
    pub members: u32,
    pub messages: u64,
    pub last_ms: u64,
    pub pending: u32,
    /// For an invitation: the endpoint ID of the person who invited me.
    pub invited_by: Option<String>,
}

impl From<&GroupInfo> for GroupRow {
    fn from(g: &GroupInfo) -> Self {
        Self {
            id: g.id.clone(),
            name: g.name.clone(),
            status: GroupStatus::parse(&g.status),
            members: g.members,
            messages: g.messages,
            last_ms: g.last_ms,
            pending: g.pending,
            invited_by: g.invited_by.clone(),
        }
    }
}

/// The invitations waiting for an answer, in list order.
pub fn invitations(rows: &[GroupRow]) -> Vec<&GroupRow> {
    rows.iter()
        .filter(|r| r.status == GroupStatus::Invited)
        .collect()
}

/// Who invited me, as the card says it: the contact's label, or a short code when the contact is
/// gone from the list, or a plain word when the service did not say.
pub fn inviter_name(g: &GroupStrings, contacts: &[ContactInfo], row: &GroupRow) -> String {
    let Some(id) = row.invited_by.as_deref() else {
        return g.inviter_unknown.to_owned();
    };
    match contacts.iter().find(|c| c.endpoint_id == id) {
        Some(c) => one_line(&c.label, NAME_CHARS),
        None => g.inviter_unknown.to_owned(),
    }
}

pub fn group_rows(list: &[GroupInfo]) -> Vec<GroupRow> {
    list.iter().map(GroupRow::from).collect()
}

/// A row of the merged conversation list: an index into the one-to-one rows or the group rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListEntry {
    Direct(usize),
    Group(usize),
}

/// Groups and one-to-one conversations in one list, newest first. On equal times the one-to-one
/// conversation comes first (a stable order, so the list does not jump).
pub fn merge_list(direct: &[ListRow], groups: &[GroupRow]) -> Vec<ListEntry> {
    let mut all: Vec<(u64, u8, usize, ListEntry)> = Vec::with_capacity(direct.len() + groups.len());
    for (i, r) in direct.iter().enumerate() {
        all.push((r.last_ms, 0, i, ListEntry::Direct(i)));
    }
    for (i, g) in groups.iter().enumerate() {
        all.push((g.last_ms, 1, i, ListEntry::Group(i)));
    }
    all.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    all.into_iter().map(|x| x.3).collect()
}

/// The same list split by kind for the two headings of the conversation list: the indexes of
/// the groups, then the indexes of the one-to-one conversations, each newest first.
pub fn split_by_kind(direct: &[ListRow], groups: &[GroupRow]) -> (Vec<usize>, Vec<usize>) {
    let (mut g, mut d) = (Vec::new(), Vec::new());
    for entry in merge_list(direct, groups) {
        match entry {
            ListEntry::Group(j) => g.push(j),
            ListEntry::Direct(i) => d.push(i),
        }
    }
    (g, d)
}

// ─── Unread ─────────────────────────────────────────────────────────────────

/// Unread messages per group, and the arrivals the navigation item still announces. The service
/// reports a message count per group, so an arrival is a count that grew while the group was not
/// on screen. The first list read only sets the baseline (nothing old is "unread").
#[derive(Debug, Default, Clone)]
pub struct GroupUnread {
    /// The count at the last list.
    known: HashMap<String, u64>,
    /// The count when the group was last on screen.
    read: HashMap<String, u64>,
    baseline: bool,
    unseen: u32,
    /// The invitations already counted for the navigation.
    invited: HashSet<String>,
}

impl GroupUnread {
    /// A fresh list of groups arrived. `viewing` is the group on screen with the tab open.
    pub fn on_list(&mut self, rows: &[GroupRow], viewing: Option<&str>, area_open: bool) {
        // A new invitation is news even on the first list: it is waiting for an answer.
        let now: HashSet<String> = invitations(rows).iter().map(|r| r.id.clone()).collect();
        let fresh = now.difference(&self.invited).count() as u32;
        self.unseen = self.unseen.saturating_add(fresh);
        self.invited = now;
        for g in rows {
            let on_screen = area_open && viewing == Some(g.id.as_str());
            let before = self.known.get(&g.id).copied();
            if !self.baseline || before.is_none() {
                // First sight of this group: what is in it is not news.
                self.read.insert(g.id.clone(), g.messages);
            } else if on_screen {
                self.read.insert(g.id.clone(), g.messages);
            } else if let Some(b) = before {
                let grown = g.messages.saturating_sub(b);
                self.unseen = self
                    .unseen
                    .saturating_add(grown.min(u64::from(u32::MAX)) as u32);
            }
            self.known.insert(g.id.clone(), g.messages);
        }
        self.baseline = true;
        let keep: HashSet<&str> = rows.iter().map(|g| g.id.as_str()).collect();
        self.known.retain(|k, _| keep.contains(k.as_str()));
        self.read.retain(|k, _| keep.contains(k.as_str()));
    }

    /// The group is on screen: everything in it is read.
    pub fn open(&mut self, id: &str, messages: u64) {
        self.read.insert(id.to_owned(), messages);
    }

    /// The tab is open: the arrivals are seen (the badges of single groups stay).
    pub fn mark_seen(&mut self) {
        self.unseen = 0;
    }

    pub fn unseen(&self) -> u32 {
        self.unseen
    }

    /// The badge of one row. An invitation counts as one.
    pub fn of(&self, g: &GroupRow) -> u32 {
        if g.status == GroupStatus::Invited {
            return 1;
        }
        let read = self.read.get(&g.id).copied().unwrap_or(g.messages);
        g.messages.saturating_sub(read).min(u64::from(u32::MAX)) as u32
    }
}

// ─── Who a message is from ──────────────────────────────────────────────────

/// A short, readable form of a verification code.
pub fn short_code(fingerprint: &str) -> String {
    fingerprint.chars().take(CODE_CHARS).collect()
}

/// Who sent a message, as the screen must say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sender {
    You,
    /// A trusted contact, by the label the person gave them.
    Contact {
        name: String,
    },
    /// Not a contact. `name` is what someone else calls them (or a short code), never checked.
    Unverified {
        name: String,
    },
}

impl Sender {
    pub fn name(&self) -> Option<&str> {
        match self {
            Sender::You => None,
            Sender::Contact { name } | Sender::Unverified { name } => Some(name),
        }
    }

    pub fn is_unverified(&self) -> bool {
        matches!(self, Sender::Unverified { .. })
    }
}

fn cleaned(name: &str) -> String {
    one_line(name, NAME_CHARS)
}

/// Who a message is from. Only a trusted contact is shown as a contact: the service says so
/// (`verified`), and a message of mine is always mine.
pub fn sender_of(g: &GroupStrings, m: &GroupMessageInfo) -> Sender {
    if m.outgoing {
        return Sender::You;
    }
    let fallback = || {
        fill(
            g.member_fallback,
            &[("code", &short_code(&m.sender_fingerprint))],
        )
    };
    if m.verified {
        let name = m
            .sender_label
            .as_deref()
            .map(cleaned)
            .filter(|n| !n.is_empty())
            .unwrap_or_else(fallback);
        return Sender::Contact { name };
    }
    let name = m
        .sender_hint
        .as_deref()
        .map(cleaned)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(fallback);
    Sender::Unverified { name }
}

/// The contact code to give to the add-contact form for a member of the group, by endpoint ID.
pub fn contact_code_of<'a>(detail: &'a GroupDetailInfo, endpoint_id: &str) -> Option<&'a str> {
    detail
        .members
        .iter()
        .find(|m| m.endpoint_id == endpoint_id && !m.you)
        .map(|m| m.contact_code.as_str())
}

/// The name of a member in the member list.
pub fn member_name(g: &GroupStrings, m: &MemberInfo) -> String {
    if m.you {
        return g.you_tag.to_owned();
    }
    let pick = |s: &Option<String>| s.as_deref().map(cleaned).filter(|n| !n.is_empty());
    if m.verified {
        if let Some(n) = pick(&m.label) {
            return n;
        }
    } else if let Some(n) = pick(&m.hint) {
        return n;
    }
    fill(g.member_fallback, &[("code", &short_code(&m.fingerprint))])
}

/// How many members (not counting me) are not contacts.
pub fn unverified_count(members: &[MemberInfo]) -> usize {
    members.iter().filter(|m| !m.you && !m.verified).count()
}

/// What the line under a member's name says, each fact once: the role, then (for others) whether
/// they are a verified contact and whether they can be reached. For me the name already says
/// "You", so only the role is left.
pub fn member_facts(g: &GroupStrings, m: &MemberInfo) -> Vec<String> {
    let role = if m.role == "admin" {
        g.role_admin
    } else {
        g.role_member
    };
    let mut facts = vec![role.to_owned()];
    if m.you {
        return facts;
    }
    facts.push(
        if m.verified {
            g.marker_verified
        } else {
            g.marker_unverified
        }
        .to_owned(),
    );
    if let Some(s) = standing_text(g, &standing_of(m)) {
        facts.push(s);
    }
    facts
}

/// The member's row as one sentence (name, then each fact once), for tests of what a screen
/// reader is told.
#[allow(dead_code)]
pub fn member_summary(g: &GroupStrings, m: &MemberInfo) -> String {
    let facts = member_facts(g, m);
    let state = facts[1..].join(g.list_sep);
    if state.is_empty() {
        return fill(
            g.a11y_member_self,
            &[("name", &member_name(g, m)), ("role", &facts[0])],
        );
    }
    fill(
        g.a11y_member,
        &[
            ("name", &member_name(g, m)),
            ("role", &facts[0]),
            ("state", &state),
        ],
    )
}

/// The muted line under a member's name in the member list (one line, cut with an ellipsis).
pub fn member_subtitle(g: &GroupStrings, m: &MemberInfo) -> String {
    member_facts(g, m).join(" - ")
}

// ─── The setting ────────────────────────────────────────────────────────────

/// `chat.group_auto_join` as saved (on when the file says nothing or cannot be read).
pub fn load_auto_join(data_dir: &std::path::Path) -> bool {
    NodeConfig::load(data_dir).map_or(true, |c| c.chat.group_auto_join)
}

/// Save `chat.group_auto_join` the way `miasma config` does: load the file, change the key, save.
pub fn save_auto_join(data_dir: &std::path::Path, on: bool) -> Result<(), String> {
    let mut c = NodeConfig::load(data_dir).map_err(|e| e.to_string())?;
    c.chat.group_auto_join = on;
    let r = c.save(data_dir).map_err(|e| e.to_string());
    c.transport.zeroize_secret_copies();
    r
}

// ─── Who has joined ─────────────────────────────────────────────────────────

/// What this device knows of one member being in the group, from the service's stable words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    You,
    Joined,
    /// Listed; nothing shows yet that they joined.
    Invited,
    /// The last attempt to reach them failed, for this reason (the service's word).
    Unreachable(String),
    /// Their Miasma has no group chat.
    NoGroupSupport,
}

pub fn standing_of(m: &MemberInfo) -> Standing {
    if m.you {
        return Standing::You;
    }
    match m.status.as_deref() {
        Some("invited") => Standing::Invited,
        Some("unreachable") => Standing::Unreachable(m.reason.clone().unwrap_or_default()),
        Some("no_group_support") => Standing::NoGroupSupport,
        // "joined", or a service that does not report it.
        _ => Standing::Joined,
    }
}

/// Why a member cannot be reached, in a few words (the service's delivery word).
pub fn reason_text(g: &GroupStrings, reason: &str) -> &'static str {
    match reason {
        "no_route" => g.reason_no_route,
        "connect_failed" | "protocol" => g.reason_connect_failed,
        "connection_lost" | "timed_out" | "bad_reply" => g.reason_connection_lost,
        "not_allowed" => g.reason_not_allowed,
        "send_disabled" => g.reason_send_disabled,
        _ => g.reason_other,
    }
}

/// The line under a member in the member list. None for me.
pub fn standing_text(g: &GroupStrings, s: &Standing) -> Option<String> {
    match s {
        Standing::You => None,
        Standing::Joined => Some(g.member_joined.to_owned()),
        Standing::Invited => Some(g.member_invited.to_owned()),
        Standing::Unreachable(r) => {
            Some(fill(g.member_unreachable, &[("reason", reason_text(g, r))]))
        }
        Standing::NoGroupSupport => Some(g.member_no_group.to_owned()),
    }
}

/// The members who have not joined or cannot be reached, by kind.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Waiting {
    pub no_group: Vec<String>,
    pub unreachable: Vec<String>,
    pub invited: Vec<String>,
}

impl Waiting {
    pub fn is_empty(&self) -> bool {
        self.no_group.is_empty() && self.unreachable.is_empty() && self.invited.is_empty()
    }
}

pub fn waiting_of(g: &GroupStrings, d: &GroupDetailInfo) -> Waiting {
    let mut w = Waiting::default();
    for m in &d.members {
        let name = elide(&member_name(g, m), NAME_CHARS);
        match standing_of(m) {
            Standing::NoGroupSupport => w.no_group.push(name),
            Standing::Unreachable(_) => w.unreachable.push(name),
            Standing::Invited => w.invited.push(name),
            Standing::You | Standing::Joined => {}
        }
    }
    w
}

fn names_list(g: &GroupStrings, names: &[String]) -> String {
    const SHOWN: usize = 3;
    let mut s = names
        .iter()
        .take(SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join(g.list_sep);
    if names.len() > SHOWN {
        s.push_str(&format!(" +{}", names.len() - SHOWN));
    }
    s
}

/// The sentences above the messages for members who have not joined or cannot be reached; the
/// flag is true for a warning. Their messages are kept and delivered later, and the sentence says
/// so.
pub fn waiting_notices(g: &GroupStrings, w: &Waiting) -> Vec<(bool, String)> {
    let mut out = Vec::new();
    if !w.no_group.is_empty() {
        out.push((
            true,
            fill(g.banner_no_group, &[("names", &names_list(g, &w.no_group))]),
        ));
    }
    if !w.unreachable.is_empty() {
        out.push((
            true,
            fill(
                g.banner_unreachable,
                &[("names", &names_list(g, &w.unreachable))],
            ),
        ));
    }
    if !w.invited.is_empty() {
        out.push((
            false,
            fill(g.banner_invited, &[("names", &names_list(g, &w.invited))]),
        ));
    }
    out
}

/// "You were added by X": the system line at the top of a group I joined through an invitation.
pub fn added_by_line(g: &GroupStrings, d: &GroupDetailInfo) -> Option<String> {
    let by = d.added_by.as_deref()?;
    Some(match d.members.iter().find(|m| m.endpoint_id == by) {
        Some(m) => fill(
            g.added_by,
            &[("who", &elide(&member_name(g, m), NAME_CHARS))],
        ),
        None => g.added_by_unknown.to_owned(),
    })
}

// ─── Delivery ───────────────────────────────────────────────────────────────

/// How far one of my messages got, as the service counts it: members it was sent to, reached, and
/// given up on. There is no "read" in groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupDelivery {
    /// Not my message, or the service gave no count.
    None,
    /// Nobody else is in the group.
    Alone,
    Waiting {
        delivered: u32,
        total: u32,
    },
    All {
        total: u32,
    },
    Partial {
        delivered: u32,
        total: u32,
        failed: u32,
    },
    FailedAll {
        total: u32,
    },
}

pub fn delivery_of(m: &GroupMessageInfo) -> GroupDelivery {
    if !m.outgoing {
        return GroupDelivery::None;
    }
    let Some(total) = m.total else {
        return GroupDelivery::None;
    };
    let delivered = m.delivered.unwrap_or(0);
    let failed = m.failed.unwrap_or(0);
    if total == 0 {
        GroupDelivery::Alone
    } else if failed == 0 && delivered >= total {
        GroupDelivery::All { total }
    } else if delivered + failed >= total && delivered == 0 {
        GroupDelivery::FailedAll { total }
    } else if failed > 0 {
        GroupDelivery::Partial {
            delivered,
            total,
            failed,
        }
    } else {
        GroupDelivery::Waiting { delivered, total }
    }
}

/// How long a message may be "waiting" before the line under it says so in full. Until then a
/// short word is enough: members who are offline are the normal case.
pub const STUCK_MS: u64 = 10 * 60_000;

/// What is drawn under one of my messages, and the exact words for the hover and the screen
/// reader when the shown line is the short one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryLine {
    pub shown: String,
    pub full: Option<String>,
}

/// The line under my message `age_ms` after it was sent. A message that is only waiting shows
/// one short word (the exact count is in `full`) until it has waited [`STUCK_MS`]; every other
/// state shows its sentence.
pub fn delivery_line(g: &GroupStrings, d: GroupDelivery, age_ms: u64) -> Option<DeliveryLine> {
    let text = delivery_text(g, d)?;
    if let GroupDelivery::Waiting { delivered, total } = d {
        if age_ms < STUCK_MS {
            // One short phrase with the count ("Waiting 0/2"), so it is clear how far the
            // message got without reading the hover text.
            return Some(DeliveryLine {
                shown: fill(
                    g.state_waiting_short,
                    &[("d", &delivered.to_string()), ("n", &total.to_string())],
                ),
                full: Some(text),
            });
        }
    }
    Some(DeliveryLine {
        shown: text,
        full: None,
    })
}

/// The sentence for a delivery state (none for a message that is not mine).
pub fn delivery_text(g: &GroupStrings, d: GroupDelivery) -> Option<String> {
    let n = |v: u32| v.to_string();
    match d {
        GroupDelivery::None => None,
        GroupDelivery::Alone => Some(g.state_alone.to_owned()),
        GroupDelivery::Waiting { delivered, total } => Some(fill(
            g.state_waiting,
            &[("d", &n(delivered)), ("n", &n(total))],
        )),
        GroupDelivery::All { total } => Some(fill(g.state_all, &[("n", &n(total))])),
        GroupDelivery::Partial {
            delivered,
            total,
            failed,
        } => Some(fill(
            g.state_partial,
            &[("d", &n(delivered)), ("n", &n(total)), ("f", &n(failed))],
        )),
        GroupDelivery::FailedAll { .. } => Some(g.state_failed_all.to_owned()),
    }
}

// ─── What the person may do ─────────────────────────────────────────────────

/// Whether "Add member" works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddCheck {
    Allowed {
        free: usize,
    },
    /// Only the creator and admins add members.
    NotAdmin,
    /// I am not in the group (any more).
    NotJoined,
    /// The group holds the most it can.
    Full,
}

pub fn free_slots(member_count: usize) -> usize {
    MAX_MEMBERS.saturating_sub(member_count)
}

pub fn add_check(d: &GroupDetailInfo) -> AddCheck {
    if GroupStatus::parse(&d.group.status) != GroupStatus::Joined {
        return AddCheck::NotJoined;
    }
    if !d.is_admin {
        return AddCheck::NotAdmin;
    }
    match free_slots(d.members.len()) {
        0 => AddCheck::Full,
        free => AddCheck::Allowed { free },
    }
}

/// "Remove" next to a member: for the creator and admins, in a group they are still in, and never
/// for oneself (that is "Leave group").
pub fn can_remove(d: &GroupDetailInfo, m: &MemberInfo) -> bool {
    d.is_admin && !m.you && GroupStatus::parse(&d.group.status) == GroupStatus::Joined
}

pub fn can_leave(status: GroupStatus) -> bool {
    status == GroupStatus::Joined
}

/// Deleting the history of a group is possible once I am out of it (the service deletes the
/// group's files from this device then).
pub fn can_delete_history(status: GroupStatus) -> bool {
    matches!(status, GroupStatus::Left | GroupStatus::Removed)
}

pub fn can_send(status: GroupStatus) -> bool {
    status == GroupStatus::Joined
}

/// The contacts that can be added to a group: sending to them is on, and they are not in it.
pub fn addable<'a>(contacts: &'a [ContactInfo], members: &[MemberInfo]) -> Vec<&'a ContactInfo> {
    let mut v: Vec<&ContactInfo> = contacts
        .iter()
        .filter(|c| c.allow_send && !members.iter().any(|m| m.endpoint_id == c.endpoint_id))
        .collect();
    v.sort_by_key(|c| c.label.to_lowercase());
    v
}

/// Every contact that may be sent to, by name (the new-group list).
pub fn selectable(contacts: &[ContactInfo]) -> Vec<&ContactInfo> {
    let mut v: Vec<&ContactInfo> = contacts.iter().filter(|c| c.allow_send).collect();
    v.sort_by_key(|c| c.label.to_lowercase());
    v
}

// ─── Forms ──────────────────────────────────────────────────────────────────

/// Contacts ticked in a list, in the order they were ticked, up to a cap.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Picks {
    chosen: Vec<String>,
}

impl Picks {
    pub fn contains(&self, id: &str) -> bool {
        self.chosen.iter().any(|c| c == id)
    }

    pub fn len(&self) -> usize {
        self.chosen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chosen.is_empty()
    }

    pub fn ids(&self) -> &[String] {
        &self.chosen
    }

    /// Tick or untick. False when ticking is refused because `cap` people are chosen already.
    pub fn set(&mut self, id: &str, on: bool, cap: usize) -> bool {
        if !on {
            self.chosen.retain(|c| c != id);
            return true;
        }
        if self.contains(id) {
            return true;
        }
        if self.chosen.len() >= cap {
            return false;
        }
        self.chosen.push(id.to_owned());
        true
    }

    /// Drop people who are not offered any more (a contact was removed meanwhile).
    pub fn retain_offered(&mut self, offered: &[&ContactInfo]) {
        self.chosen.retain(|c| offered.iter().any(|o| &o.id == c));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormError {
    Name,
    /// The name is over the product limit (see [`name_fit`]).
    NameTooLong(NameFit),
    NoMembers,
    TooMany,
}

/// Longest group name the form accepts, in characters, in every language. The wire limit
/// (`MAX_NAME_BYTES`, 192 bytes) is not changed: a name must also fit it, which 64 characters
/// of any script do unless they are mostly 4-byte characters such as emoji.
pub const NAME_MAX_CHARS: usize = 64;

/// How much of the name box is kept in memory when text is pasted (far above any limit, so a
/// paste is never silently cut to the limit; the form says it is too long instead).
pub const NAME_KEEP_BYTES: usize = MAX_NAME_BYTES * 4;

/// Whether a typed group name fits, and which limit it hits first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameFit {
    Ok,
    /// More than [`NAME_MAX_CHARS`] characters; the number is how many too many.
    OverChars(usize),
    /// Within the character limit but over `MAX_NAME_BYTES` (emoji and some symbols take 4
    /// bytes); the number is the approximate count of characters to remove.
    OverBytes(usize),
}

/// The rule: at most [`NAME_MAX_CHARS`] characters AND at most `MAX_NAME_BYTES` bytes, measured
/// on the trimmed name (the one that is sent).
pub fn name_fit(name: &str) -> NameFit {
    let t = name.trim();
    let chars = t.chars().count();
    if chars > NAME_MAX_CHARS {
        return NameFit::OverChars(chars - NAME_MAX_CHARS);
    }
    if t.len() > MAX_NAME_BYTES {
        let avg = t.len() as f64 / chars.max(1) as f64;
        let over = ((t.len() - MAX_NAME_BYTES) as f64 / avg).ceil() as usize;
        return NameFit::OverBytes(over.max(1));
    }
    NameFit::Ok
}

/// The line under the name box: the count while it fits, which limit was hit when it does not.
pub fn name_fit_text(g: &GroupStrings, name: &str) -> String {
    match name_fit(name) {
        NameFit::Ok => fill(
            g.ng_name_count,
            &[
                ("n", &name.trim().chars().count().to_string()),
                ("max", &NAME_MAX_CHARS.to_string()),
            ],
        ),
        over => name_over_text(g, over),
    }
}

/// Which limit was hit, in words (empty when the name fits).
pub fn name_over_text(g: &GroupStrings, fit: NameFit) -> String {
    match fit {
        NameFit::Ok => String::new(),
        NameFit::OverChars(n) => fill(
            g.ng_name_over_chars,
            &[("n", &n.to_string()), ("max", &NAME_MAX_CHARS.to_string())],
        ),
        NameFit::OverBytes(n) => fill(g.ng_name_over_bytes, &[("n", &n.to_string())]),
    }
}

/// From this many contacts on, the pickers get a search field and a "selected only" switch.
pub const PICKER_SEARCH_MIN: usize = 8;

/// The contacts a picker shows: those whose name contains `query` (case-insensitive; an empty
/// query matches all), and with `selected_only` only the ticked ones. The order is kept.
pub fn filter_picker<'a>(
    offered: &[&'a ContactInfo],
    query: &str,
    selected_only: bool,
    picks: &Picks,
) -> Vec<&'a ContactInfo> {
    let q = query.trim().to_lowercase();
    offered
        .iter()
        .copied()
        .filter(|c| q.is_empty() || c.label.to_lowercase().contains(&q))
        .filter(|c| !selected_only || picks.contains(&c.id))
        .collect()
}

/// The new-group form.
#[derive(Debug, Default, Clone)]
pub struct NewGroupForm {
    pub name: String,
    pub picks: Picks,
    /// The contact search (only drawn from [`PICKER_SEARCH_MIN`] contacts on).
    pub search: String,
    pub selected_only: bool,
    /// Set when ticking was refused; cleared by the next change.
    pub error: Option<FormError>,
}

impl NewGroupForm {
    /// People other than me that fit.
    pub const CAP: usize = MAX_MEMBERS - 1;

    /// Members including me.
    pub fn total(&self) -> usize {
        self.picks.len() + 1
    }

    pub fn tick(&mut self, id: &str, on: bool) {
        self.error = if self.picks.set(id, on, Self::CAP) {
            None
        } else {
            Some(FormError::TooMany)
        };
    }

    pub fn edit_name(&mut self) {
        cap_text(&mut self.name, NAME_KEEP_BYTES);
        if matches!(
            self.error,
            Some(FormError::Name | FormError::NameTooLong(_))
        ) {
            self.error = None;
        }
    }

    /// The name and the contacts to send, or what is missing.
    pub fn check(&self) -> Result<(String, Vec<String>), FormError> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err(FormError::Name);
        }
        if self.picks.is_empty() {
            return Err(FormError::NoMembers);
        }
        if self.total() > MAX_MEMBERS {
            return Err(FormError::TooMany);
        }
        let fit = name_fit(name);
        if fit != NameFit::Ok {
            return Err(FormError::NameTooLong(fit));
        }
        Ok((name.to_owned(), self.picks.ids().to_vec()))
    }
}

pub fn form_error_text(g: &GroupStrings, e: FormError) -> String {
    match e {
        FormError::Name => g.ng_err_name.to_owned(),
        FormError::NameTooLong(fit) => name_over_text(g, fit),
        FormError::NoMembers => g.ng_err_members.to_owned(),
        FormError::TooMany => fill(g.ng_err_limit, &[("max", &MAX_MEMBERS.to_string())]),
    }
}

// ─── Words ──────────────────────────────────────────────────────────────────

/// The sentence for an error answer, from the service's stable kind. Kinds that mean the same as
/// in a one-to-one chat use that chat's sentence.
pub fn error_text(g: &GroupStrings, c: &ChatStrings, kind: &str) -> String {
    let max = MAX_MEMBERS.to_string();
    match kind {
        "unknown_group" => g.err_unknown_group.to_owned(),
        "ambiguous_group" => g.err_ambiguous_group.to_owned(),
        "not_joined" => g.err_not_joined.to_owned(),
        "not_admin" => g.err_not_admin.to_owned(),
        "not_member" => g.err_not_member.to_owned(),
        "already_member" => g.err_already_member.to_owned(),
        "too_many_groups" => fill(g.err_too_many_groups, &[("max", &MAX_GROUPS.to_string())]),
        "too_many_members" => fill(g.err_too_many_members, &[("max", &max)]),
        "last_admin" => g.err_last_admin.to_owned(),
        "queue_full" => g.err_queue_full.to_owned(),
        "bad_request" => g.err_bad_request.to_owned(),
        "unavailable" => g.unavailable.to_owned(),
        "empty" | "too_big" | "send_disabled" | "unknown_contact" | "internal" => {
            crate::chat::error_text(c, kind).to_owned()
        }
        _ => c.err_other.to_owned(),
    }
}

/// What the list shows under a group's name: the last message with its sender, or the state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupLast {
    None,
    Message { sender: Sender, text: String },
}

pub fn last_of(g: &GroupStrings, messages: &[GroupMessageInfo]) -> GroupLast {
    match messages.last() {
        Some(m) => GroupLast::Message {
            sender: sender_of(g, m),
            text: one_line(&m.text, PREVIEW_CHARS),
        },
        None => GroupLast::None,
    }
}

/// The second line of a group row.
pub fn preview_line(g: &GroupStrings, c: &ChatStrings, row: &GroupRow, last: &GroupLast) -> String {
    let members = fill(g.row_members, &[("n", &row.members.to_string())]);
    let tail = preview_tail(g, c, row, last);
    if tail.is_empty() {
        members
    } else {
        format!("{members} | {tail}")
    }
}

/// What a group row's second line says after the member count: the state, or the last message
/// with its sender. Empty when there is nothing.
pub fn preview_tail(g: &GroupStrings, c: &ChatStrings, row: &GroupRow, last: &GroupLast) -> String {
    match row.status {
        GroupStatus::Invited => g.row_invited.to_owned(),
        GroupStatus::Left => g.row_left.to_owned(),
        GroupStatus::Removed => g.row_removed.to_owned(),
        _ => match last {
            GroupLast::None => String::new(),
            GroupLast::Message { sender, text } => match sender {
                Sender::You => fill(c.preview_you, &[("text", text)]),
                other => fill(
                    g.preview_sender,
                    &[("name", other.name().unwrap_or("")), ("text", text)],
                ),
            },
        },
    }
}

/// The screen-reader name of a group row.
pub fn row_label(g: &GroupStrings, row: &GroupRow) -> String {
    fill(
        g.a11y_row,
        &[
            ("name", &elide(&row.name, NAME_CHARS)),
            ("n", &row.members.to_string()),
        ],
    )
}

/// The whole screen-reader name of a group row: the name and member count once, then the unread
/// count, then what follows the member count on the visible second line (the last message or the
/// state). `preview_line` starts with the member count for the eye; the name must not repeat it.
pub fn row_a11y(
    g: &GroupStrings,
    c: &ChatStrings,
    row: &GroupRow,
    last: &GroupLast,
    unread: u32,
) -> String {
    let mut s = row_label(g, row);
    if unread > 0 {
        s.push_str(g.list_sep);
        s.push_str(&fill(
            c.a11y_unread,
            &[("n", &crate::chat::badge_text(unread))],
        ));
    }
    let tail = preview_tail(g, c, row, last);
    if !tail.is_empty() {
        s.push_str(g.list_sep);
        s.push_str(&tail);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locale::{chat_strings, group_strings, Locale};
    use crate::theme::{contrast, Palette};

    fn g() -> &'static GroupStrings {
        group_strings(Locale::En)
    }

    fn info(id: &str, status: &str, members: u32, messages: u64, last_ms: u64) -> GroupInfo {
        GroupInfo {
            id: id.into(),
            name: format!("group {id}"),
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
            fingerprint: format!("FP{ep}-AAAA-BBBB-CCCC"),
            contact_code: format!("CODE-{ep}"),
            role: if admin { "admin" } else { "member" }.into(),
            hint: (!verified && !you).then(|| format!("hint {ep}")),
            label: verified.then(|| format!("label {ep}")),
            verified,
            you,
            status: Some(if you { "you" } else { "joined" }.into()),
            reason: None,
        }
    }

    fn detail(status: &str, is_admin: bool, members: Vec<MemberInfo>) -> GroupDetailInfo {
        GroupDetailInfo {
            group: info("1", status, members.len() as u32, 0, 0),
            members,
            is_admin,
            added_by: None,
        }
    }

    fn msg(outgoing: bool, verified: bool) -> GroupMessageInfo {
        GroupMessageInfo {
            ord: 1,
            id: "m1".into(),
            outgoing,
            sender: "ep".into(),
            sender_label: verified.then(|| "Alice".into()),
            sender_hint: Some("Bob says".into()),
            sender_fingerprint: "ABCD-EFGH-IJKL-MNOP".into(),
            verified,
            counter: 1,
            epoch: 1,
            text: "hello".into(),
            sent_ms: 1,
            at_ms: 1,
            total: outgoing.then_some(3),
            delivered: outgoing.then_some(0),
            failed: outgoing.then_some(0),
            gap_before: 0,
        }
    }

    fn contact(id: &str, ep: &str, send: bool) -> ContactInfo {
        ContactInfo {
            id: id.into(),
            label: format!("Contact {id}"),
            endpoint_id: ep.into(),
            fingerprint: String::new(),
            added_at: 0,
            allow_send: send,
            allow_receive: true,
            max_file_size: None,
            default_max_file_size: 0,
            inbox_dir: String::new(),
        }
    }

    #[test]
    fn groups_and_conversations_share_one_list_newest_first() {
        let direct = vec![
            ListRow {
                endpoint_id: "e1".into(),
                contact_id: "c1".into(),
                label: "A".into(),
                last_ms: 300,
                messages: 1,
                pending: 0,
            },
            ListRow {
                endpoint_id: "e2".into(),
                contact_id: "c2".into(),
                label: "B".into(),
                last_ms: 100,
                messages: 1,
                pending: 0,
            },
        ];
        let groups = group_rows(&[
            info("g1", "joined", 3, 5, 200),
            info("g2", "joined", 3, 5, 300),
        ]);
        assert_eq!(
            merge_list(&direct, &groups),
            vec![
                ListEntry::Direct(0),
                ListEntry::Group(1),
                ListEntry::Group(0),
                ListEntry::Direct(1)
            ]
        );
        assert!(merge_list(&[], &[]).is_empty());
        // Split under two headings, each part keeping the newest-first order.
        assert_eq!(split_by_kind(&direct, &groups), (vec![1, 0], vec![0, 1]));
        assert_eq!(split_by_kind(&[], &[]), (vec![], vec![]));
    }

    #[test]
    fn a_message_of_a_non_contact_is_unverified_whatever_the_name_says() {
        let s = sender_of(g(), &msg(false, false));
        assert_eq!(
            s,
            Sender::Unverified {
                name: "Bob says".into()
            }
        );
        assert!(s.is_unverified());
        // The service says the sender is a contact: shown by the contact's own label.
        assert_eq!(
            sender_of(g(), &msg(false, true)),
            Sender::Contact {
                name: "Alice".into()
            }
        );
        // My own message is mine, never unverified.
        assert_eq!(sender_of(g(), &msg(true, false)), Sender::You);
    }

    #[test]
    fn an_unverified_sender_without_a_name_is_shown_by_a_short_code() {
        let mut m = msg(false, false);
        m.sender_hint = None;
        let Sender::Unverified { name } = sender_of(g(), &m) else {
            panic!("expected unverified");
        };
        assert_eq!(name, "Member ABCD-EFGH-IJKL");
        // A hint with line breaks and tabs stays on one line.
        m.sender_hint = Some("Bob\n\tsays".into());
        let Sender::Unverified { name } = sender_of(g(), &m) else {
            panic!("expected unverified");
        };
        assert_eq!(name, "Bob says");
    }

    #[test]
    fn the_add_as_contact_code_comes_from_the_member_list_and_never_for_me() {
        let d = detail(
            "joined",
            true,
            vec![
                member("me", true, false, true),
                member("ep", false, false, false),
            ],
        );
        assert_eq!(contact_code_of(&d, "ep"), Some("CODE-ep"));
        assert_eq!(contact_code_of(&d, "me"), None);
        assert_eq!(contact_code_of(&d, "gone"), None);
    }

    #[test]
    fn members_are_marked_by_state_and_counted() {
        let ms = vec![
            member("me", true, false, true),
            member("a", false, true, false),
            member("b", false, false, false),
            member("c", false, false, false),
        ];
        assert_eq!(unverified_count(&ms), 2);
        assert_eq!(member_name(g(), &ms[0]), "You");
        assert_eq!(member_name(g(), &ms[1]), "label a");
        assert_eq!(member_name(g(), &ms[2]), "hint b");
        assert!(member_summary(g(), &ms[1]).contains("Verified contact"));
        assert!(member_summary(g(), &ms[2]).contains("Unverified"));
        assert!(member_summary(g(), &ms[0]).contains("Admin"));
    }

    #[test]
    fn delivery_is_what_the_service_counts() {
        let mut m = msg(true, false);
        for (t, d, f, want) in [
            (
                3,
                0,
                0,
                GroupDelivery::Waiting {
                    delivered: 0,
                    total: 3,
                },
            ),
            (
                3,
                2,
                0,
                GroupDelivery::Waiting {
                    delivered: 2,
                    total: 3,
                },
            ),
            (3, 3, 0, GroupDelivery::All { total: 3 }),
            (
                3,
                2,
                1,
                GroupDelivery::Partial {
                    delivered: 2,
                    total: 3,
                    failed: 1,
                },
            ),
            (3, 0, 3, GroupDelivery::FailedAll { total: 3 }),
            (0, 0, 0, GroupDelivery::Alone),
        ] {
            m.total = Some(t);
            m.delivered = Some(d);
            m.failed = Some(f);
            assert_eq!(delivery_of(&m), want, "{t}/{d}/{f}");
        }
        // Not mine: no state. No count: no state.
        assert_eq!(delivery_of(&msg(false, true)), GroupDelivery::None);
        m.total = None;
        assert_eq!(delivery_of(&m), GroupDelivery::None);
        assert_eq!(delivery_text(g(), GroupDelivery::None), None);
        assert_eq!(
            delivery_text(g(), GroupDelivery::All { total: 3 }).as_deref(),
            Some("Delivered to all 3 members")
        );
        // No read state exists in groups.
        for lang in Locale::ALL {
            let t = delivery_text(
                group_strings(lang),
                GroupDelivery::Waiting {
                    delivered: 1,
                    total: 3,
                },
            )
            .unwrap();
            assert!(t.contains('1') && t.contains('3'), "{lang:?}: {t}");
        }
    }

    #[test]
    fn only_admins_add_and_remove_and_the_limit_is_checked() {
        let many = |n: usize, admin: bool| {
            let mut v = vec![member("me", true, false, admin)];
            for i in 1..n {
                v.push(member(&format!("m{i}"), false, true, false));
            }
            detail("joined", admin, v)
        };
        assert_eq!(add_check(&many(5, true)), AddCheck::Allowed { free: 27 });
        assert_eq!(add_check(&many(5, false)), AddCheck::NotAdmin);
        assert_eq!(add_check(&many(MAX_MEMBERS, true)), AddCheck::Full);
        assert_eq!(
            add_check(&many(MAX_MEMBERS - 1, true)),
            AddCheck::Allowed { free: 1 }
        );
        assert_eq!(
            add_check(&detail("left", true, vec![member("me", true, false, true)])),
            AddCheck::NotJoined
        );
        let admin = many(3, true);
        let plain = many(3, false);
        assert!(can_remove(&admin, &admin.members[1]));
        assert!(!can_remove(&admin, &admin.members[0]), "not oneself");
        assert!(!can_remove(&plain, &plain.members[1]), "members cannot");
        let gone = detail(
            "removed",
            true,
            vec![
                member("me", true, false, true),
                member("x", false, true, false),
            ],
        );
        assert!(!can_remove(&gone, &gone.members[1]), "not once out");
    }

    #[test]
    fn leaving_sending_and_deleting_follow_the_status() {
        for (s, leave, send, delete) in [
            (GroupStatus::Joined, true, true, false),
            (GroupStatus::Left, false, false, true),
            (GroupStatus::Removed, false, false, true),
            (GroupStatus::Invited, false, false, false),
            (GroupStatus::Other, false, false, false),
        ] {
            assert_eq!(can_leave(s), leave, "{s:?}");
            assert_eq!(can_send(s), send, "{s:?}");
            assert_eq!(can_delete_history(s), delete, "{s:?}");
        }
    }

    #[test]
    fn only_contacts_who_can_be_sent_to_and_are_not_in_the_group_are_offered() {
        let contacts = vec![
            contact("1", "ep1", true),
            contact("2", "ep2", false),
            contact("3", "ep3", true),
        ];
        let members = vec![member("ep1", false, true, false)];
        let offered = addable(&contacts, &members);
        assert_eq!(offered.len(), 1);
        assert_eq!(offered[0].id, "3");
        assert_eq!(selectable(&contacts).len(), 2);
    }

    #[test]
    fn the_new_group_form_checks_name_members_and_the_limit() {
        let mut f = NewGroupForm::default();
        assert_eq!(f.check().unwrap_err(), FormError::Name);
        f.name = "  Team  ".into();
        assert_eq!(f.check().unwrap_err(), FormError::NoMembers);
        f.tick("c1", true);
        assert_eq!(
            f.check().unwrap(),
            ("Team".to_owned(), vec!["c1".to_owned()])
        );
        assert_eq!(f.total(), 2);
        // Ticking twice does not duplicate; unticking removes.
        f.tick("c1", true);
        assert_eq!(f.picks.len(), 1);
        f.tick("c1", false);
        assert!(f.picks.is_empty());
        // The limit counts me: 31 others fit, the 32nd is refused with the limit message.
        for i in 0..NewGroupForm::CAP {
            f.tick(&format!("c{i}"), true);
            assert_eq!(f.error, None);
        }
        assert_eq!(f.total(), MAX_MEMBERS);
        f.tick("one-too-many", true);
        assert_eq!(f.error, Some(FormError::TooMany));
        assert_eq!(f.picks.len(), NewGroupForm::CAP);
        assert!(!f.picks.contains("one-too-many"));
        assert_eq!(
            form_error_text(g(), FormError::TooMany),
            "A group holds at most 32 members, including you."
        );
        // Unticking one makes room again and clears the message.
        f.tick("c0", false);
        assert_eq!(f.error, None);
        // A very long name is kept as typed (not cut); the form refuses it and says why.
        f.name = "あ".repeat(200);
        f.edit_name();
        assert_eq!(f.name.chars().count(), 200);
        assert_eq!(
            f.check().unwrap_err(),
            FormError::NameTooLong(NameFit::OverChars(200 - NAME_MAX_CHARS))
        );
    }

    #[test]
    fn a_group_name_has_the_same_limit_in_characters_in_every_script() {
        // 64 characters of one, two or three bytes each fit the wire limit; the 65th does not.
        for ch in ["a", "é", "あ", "中"] {
            assert_eq!(name_fit(&ch.repeat(NAME_MAX_CHARS)), NameFit::Ok, "{ch}");
            assert_eq!(
                name_fit(&ch.repeat(NAME_MAX_CHARS + 1)),
                NameFit::OverChars(1),
                "{ch}"
            );
        }
        // Surrounding blanks do not count, they are not sent.
        assert_eq!(name_fit(&format!("  {}  ", "a".repeat(64))), NameFit::Ok);
        // 4-byte characters hit the byte limit first: 48 fit (192 bytes), 49 do not.
        assert_eq!(name_fit(&"😀".repeat(48)), NameFit::Ok);
        assert_eq!(name_fit(&"😀".repeat(49)), NameFit::OverBytes(1));
        assert_eq!(name_fit(&"😀".repeat(64)), NameFit::OverBytes(16));
        // Whatever fits is accepted by the wire rule.
        let mut f = NewGroupForm::default();
        f.tick("c1", true);
        f.name = "😀".repeat(48);
        assert!(f.check().is_ok());
        assert!(f.name.len() <= MAX_NAME_BYTES);
    }

    #[test]
    fn a_long_paste_is_kept_and_the_line_under_the_name_says_which_limit_was_hit() {
        use crate::locale::{group_strings, Locale};
        for locale in Locale::ALL {
            let g = group_strings(locale);
            let mut f = NewGroupForm::default();
            f.name = "a".repeat(300);
            f.edit_name();
            assert_eq!(f.name.len(), 300, "{locale:?}: a paste is not cut");
            let over = name_fit_text(g, &f.name);
            assert!(over.contains("236"), "{locale:?}: {over}");
            assert!(over.contains("64"), "{locale:?}: {over}");
            // The count while it fits.
            let ok = name_fit_text(g, "abc");
            assert!(ok.contains('3') && ok.contains("64"), "{locale:?}: {ok}");
            // Only the emoji case mentions room, not a character count of the limit.
            let emoji = name_fit_text(g, &"😀".repeat(60));
            assert!(emoji.contains("12"), "{locale:?}: {emoji}");
            // The error kept on the form, once the name changes, goes away.
            f.tick("c1", true);
            f.error = f.check().err();
            assert!(matches!(f.error, Some(FormError::NameTooLong(_))));
            f.name = "ok".into();
            f.edit_name();
            assert_eq!(f.error, None);
        }
    }

    #[test]
    fn the_add_picker_stops_at_the_free_slots() {
        let mut p = Picks::default();
        assert!(p.set("a", true, 2));
        assert!(p.set("b", true, 2));
        assert!(!p.set("c", true, 2));
        assert_eq!(p.ids(), ["a".to_owned(), "b".to_owned()]);
        assert!(p.set("a", false, 2));
        assert!(p.set("c", true, 2));
        let contacts = vec![contact("c", "e", true)];
        let offered: Vec<&ContactInfo> = contacts.iter().collect();
        p.retain_offered(&offered);
        assert_eq!(p.ids(), ["c".to_owned()]);
    }

    #[test]
    fn unread_starts_from_the_first_list_and_counts_what_arrives_off_screen() {
        let mut u = GroupUnread::default();
        let rows = |n: u64| {
            group_rows(&[
                info("g1", "joined", 3, n, 10),
                info("g2", "joined", 3, 4, 10),
            ])
        };
        // First list: nothing is unread.
        u.on_list(&rows(5), None, true);
        assert_eq!(u.of(&rows(5)[0]), 0);
        assert_eq!(u.unseen(), 0);
        // Two messages arrive in g1 while it is not on screen.
        u.on_list(&rows(7), None, true);
        assert_eq!(u.of(&rows(7)[0]), 2);
        assert_eq!(u.of(&rows(7)[1]), 0);
        assert_eq!(u.unseen(), 2);
        // The tab is seen: the nav announcement goes, the badge stays.
        u.mark_seen();
        assert_eq!(u.unseen(), 0);
        assert_eq!(u.of(&rows(7)[0]), 2);
        // Opening it reads it; more arrivals while it is on screen are read at once.
        u.open("g1", 7);
        assert_eq!(u.of(&rows(7)[0]), 0);
        u.on_list(&rows(8), Some("g1"), true);
        assert_eq!(u.of(&rows(8)[0]), 0);
        assert_eq!(u.unseen(), 0);
        // On screen but the tab is closed: counted as unread.
        u.on_list(&rows(9), Some("g1"), false);
        assert_eq!(u.of(&rows(9)[0]), 1);
        assert_eq!(u.unseen(), 1);
        // A group that is gone is forgotten.
        u.on_list(&rows(9)[1..], None, true);
        assert!(!u.known.contains_key("g1"));
    }

    #[test]
    fn an_invitation_shows_one_unread_and_a_new_group_is_not_news() {
        let mut u = GroupUnread::default();
        let first = group_rows(&[info("g1", "joined", 2, 3, 1)]);
        u.on_list(&first, None, true);
        let next = group_rows(&[
            info("g1", "joined", 2, 3, 1),
            info("g3", "invited", 2, 0, 2),
        ]);
        u.on_list(&next, None, true);
        assert_eq!(u.of(&next[1]), 1);
        assert_eq!(
            u.unseen(),
            1,
            "the invitation is news: it waits for an answer"
        );
        let both = group_rows(&[
            info("g1", "joined", 2, 3, 1),
            info("g3", "invited", 2, 0, 2),
            info("g4", "joined", 2, 0, 3),
        ]);
        u.on_list(&both, None, true);
        assert_eq!(u.unseen(), 1, "a group appearing is not a message");
    }

    #[test]
    fn rows_say_what_they_are_in_every_language() {
        let row = GroupRow::from(&info("g1", "joined", 4, 2, 5));
        let last = GroupLast::Message {
            sender: Sender::Unverified { name: "Bob".into() },
            text: "hi".into(),
        };
        for lang in Locale::ALL {
            let (gs, cs) = (group_strings(lang), chat_strings(lang));
            let line = preview_line(gs, cs, &row, &last);
            assert!(
                line.contains('4') && line.contains("Bob") && line.contains("hi"),
                "{line}"
            );
            assert!(row_label(gs, &row).contains('4'));
            let mine = GroupLast::Message {
                sender: Sender::You,
                text: "yo".into(),
            };
            assert!(preview_line(gs, cs, &row, &mine).contains("yo"));
            let invited = GroupRow::from(&info("g2", "invited", 4, 0, 5));
            assert!(preview_line(gs, cs, &invited, &GroupLast::None).contains(gs.row_invited));
        }
        assert_eq!(
            preview_line(g(), chat_strings(Locale::En), &row, &GroupLast::None),
            "4 members"
        );
    }

    #[test]
    fn a_group_row_is_read_with_each_fact_once() {
        // The visible second line starts with the member count; the screen-reader name already
        // has it, so it must not be read twice ("Group X, 3 members, 3 members | You: test").
        let row = GroupRow::from(&info("g1", "joined", 3, 2, 5));
        let mine = GroupLast::Message {
            sender: Sender::You,
            text: "test".into(),
        };
        for lang in Locale::ALL {
            let (gs, cs) = (group_strings(lang), chat_strings(lang));
            let count = fill(gs.row_members, &[("n", "3")]);
            for unread in [0, 2] {
                let name = row_a11y(gs, cs, &row, &mine, unread);
                assert_eq!(name.matches(&count).count(), 1, "{lang:?}: {name}");
                assert!(name.contains("test") && name.contains("group g1"), "{name}");
            }
            let invited = GroupRow::from(&info("g2", "invited", 3, 0, 5));
            let name = row_a11y(gs, cs, &invited, &GroupLast::None, 1);
            assert_eq!(name.matches(&count).count(), 1, "{lang:?}: {name}");
            assert!(name.contains(gs.row_invited), "{name}");
        }
        assert_eq!(
            row_a11y(g(), chat_strings(Locale::En), &row, &mine, 0),
            "Group group g1, 3 members, You: test"
        );
    }

    #[test]
    fn a_member_is_read_with_each_fact_once() {
        let ms = vec![
            member("me", true, false, true),
            member("a", false, true, false),
            member("b", false, false, true),
        ];
        for lang in Locale::ALL {
            let gs = group_strings(lang);
            // Me: the name already says "You", and the role follows; nothing says "You" again.
            let me = member_summary(gs, &ms[0]);
            assert_eq!(me.matches(gs.you_tag).count(), 1, "{lang:?}: {me}");
            assert_eq!(member_facts(gs, &ms[0]), vec![gs.role_admin.to_owned()]);
            // Others: role, verified marker (once) and standing.
            let a = member_summary(gs, &ms[1]);
            assert_eq!(a.matches(gs.marker_verified).count(), 1, "{lang:?}: {a}");
            assert_eq!(a.matches(gs.role_member).count(), 1, "{lang:?}: {a}");
            let b = member_summary(gs, &ms[2]);
            assert_eq!(b.matches(gs.role_admin).count(), 1, "{lang:?}: {b}");
        }
        assert_eq!(member_summary(g(), &ms[0]), "You, Admin");
        assert_eq!(member_subtitle(g(), &ms[0]), "Admin");
        assert_eq!(
            member_subtitle(g(), &ms[1]),
            "Member - Verified contact - Joined"
        );
    }

    #[test]
    fn waiting_is_one_short_word_until_it_has_waited_long() {
        for lang in Locale::ALL {
            let gs = group_strings(lang);
            let waiting = GroupDelivery::Waiting {
                delivered: 0,
                total: 2,
            };
            let quick = delivery_line(gs, waiting, 30_000).expect("a line");
            // The short phrase carries the count: how many of the 2 got it so far (0).
            assert_eq!(
                quick.shown,
                fill(gs.state_waiting_short, &[("d", "0"), ("n", "2")])
            );
            assert!(quick.shown.contains('0') && quick.shown.contains('2'));
            let full = quick.full.expect("the exact count is kept for the hover");
            assert!(full.contains('2') && full.contains('0'), "{full}");
            assert!(full.chars().count() > quick.shown.chars().count());
            // Stuck: the sentence is shown in full.
            let stuck = delivery_line(gs, waiting, STUCK_MS).expect("a line");
            assert_eq!(stuck.shown, full);
            assert_eq!(stuck.full, None);
        }
        // Only "waiting" is shortened.
        let all = delivery_line(g(), GroupDelivery::All { total: 2 }, 0).unwrap();
        assert_eq!(all.shown, "Delivered to all 2 members");
        assert_eq!(all.full, None);
        assert_eq!(delivery_line(g(), GroupDelivery::None, 0), None);
    }

    fn named_contact(id: &str, label: &str) -> ContactInfo {
        ContactInfo {
            id: id.into(),
            label: label.into(),
            endpoint_id: format!("ep-{id}"),
            fingerprint: String::new(),
            added_at: 0,
            allow_send: true,
            allow_receive: true,
            max_file_size: None,
            default_max_file_size: 0,
            inbox_dir: String::new(),
        }
    }

    #[test]
    fn the_picker_is_filtered_by_name_and_by_what_is_ticked() {
        let list: Vec<ContactInfo> = ["Alice", "Bob", "alicia", "Carol"]
            .iter()
            .enumerate()
            .map(|(i, n)| named_contact(&format!("c{i}"), n))
            .collect();
        let offered: Vec<&ContactInfo> = list.iter().collect();
        let mut picks = Picks::default();
        picks.set("c1", true, 31);
        picks.set("c3", true, 31);
        let names = |v: Vec<&ContactInfo>| v.iter().map(|c| c.label.clone()).collect::<Vec<_>>();
        assert_eq!(names(filter_picker(&offered, "", false, &picks)).len(), 4);
        assert_eq!(
            names(filter_picker(&offered, "ALI", false, &picks)),
            ["Alice", "alicia"]
        );
        assert_eq!(
            names(filter_picker(&offered, "  ", true, &picks)),
            ["Bob", "Carol"]
        );
        assert_eq!(
            names(filter_picker(&offered, "o", true, &picks)),
            ["Bob", "Carol"]
        );
        assert!(filter_picker(&offered, "zzz", false, &picks).is_empty());
        // Hiding a ticked contact by the filter does not untick it.
        assert!(picks.contains("c1"));
        assert_eq!(PICKER_SEARCH_MIN, 8);
    }

    #[test]
    fn every_error_kind_has_a_sentence_in_every_language() {
        for lang in Locale::ALL {
            let (gs, cs) = (group_strings(lang), chat_strings(lang));
            for kind in [
                "unavailable",
                "unknown_contact",
                "send_disabled",
                "unknown_group",
                "ambiguous_group",
                "not_joined",
                "not_admin",
                "not_member",
                "already_member",
                "too_many_groups",
                "too_many_members",
                "last_admin",
                "queue_full",
                "empty",
                "too_big",
                "bad_request",
                "internal",
                "something_new",
            ] {
                let t = error_text(gs, cs, kind);
                assert!(!t.trim().is_empty(), "{lang:?} {kind}");
                assert!(!t.contains('{'), "{lang:?} {kind}: {t}");
            }
        }
        assert!(error_text(g(), chat_strings(Locale::En), "too_many_members").contains("32"));
        assert_eq!(
            error_text(g(), chat_strings(Locale::En), "not_admin"),
            g().err_not_admin
        );
    }

    fn with_status(mut m: MemberInfo, status: &str, reason: Option<&str>) -> MemberInfo {
        m.status = Some(status.into());
        m.reason = reason.map(str::to_owned);
        m
    }

    #[test]
    fn each_member_shows_whether_they_joined_cannot_be_reached_or_need_an_update() {
        let ms = [
            member("me", true, false, true),
            with_status(member("amy", false, true, false), "joined", None),
            with_status(member("bob", false, true, false), "invited", None),
            with_status(
                member("cy", false, true, false),
                "unreachable",
                Some("no_route"),
            ),
            with_status(member("dee", false, true, false), "no_group_support", None),
        ];
        let want = [
            Standing::You,
            Standing::Joined,
            Standing::Invited,
            Standing::Unreachable("no_route".into()),
            Standing::NoGroupSupport,
        ];
        for (m, w) in ms.iter().zip(&want) {
            assert_eq!(&standing_of(m), w);
        }
        for lang in crate::locale::Locale::ALL {
            let g = crate::locale::group_strings(lang);
            assert_eq!(standing_text(g, &Standing::You), None);
            for s in &want[1..] {
                let t = standing_text(g, s).expect("a sentence");
                assert!(!t.contains('{'), "{lang:?}: {t}");
            }
        }
        assert_eq!(
            standing_text(g(), &want[2]).as_deref(),
            Some("Invited, waiting for them to accept")
        );
        assert!(standing_text(g(), &want[3])
            .unwrap()
            .contains("they seem to be offline"));
        assert!(standing_text(g(), &want[4])
            .unwrap()
            .contains("does not support groups"));
        // A service that reports nothing is read as joined, not as a problem.
        let mut old = member("old", false, true, false);
        old.status = None;
        assert_eq!(standing_of(&old), Standing::Joined);
        // The screen-reader name carries it too.
        assert!(member_summary(g(), &ms[2]).contains("waiting for them to accept"));
    }

    #[test]
    fn the_notes_above_the_messages_name_who_is_waiting_and_say_the_messages_are_kept() {
        let d = detail(
            "joined",
            true,
            vec![
                member("me", true, false, true),
                with_status(member("bob", false, true, false), "invited", None),
                with_status(
                    member("cy", false, true, false),
                    "unreachable",
                    Some("connect_failed"),
                ),
                with_status(member("dee", false, true, false), "no_group_support", None),
            ],
        );
        let w = waiting_of(g(), &d);
        assert_eq!(w.invited, vec!["label bob".to_owned()]);
        assert_eq!(w.unreachable, vec!["label cy".to_owned()]);
        assert_eq!(w.no_group, vec!["label dee".to_owned()]);
        let n = waiting_notices(g(), &w);
        assert_eq!(n.len(), 3);
        assert!(n[0].0 && n[0].1.contains("label dee") && n[0].1.contains("update"));
        assert!(n[1].0 && n[1].1.contains("label cy"));
        assert!(!n[2].0 && n[2].1.contains("label bob") && n[2].1.contains("kept"));
        // Everyone joined: nothing to say.
        let ok = detail(
            "joined",
            true,
            vec![
                member("me", true, false, true),
                member("amy", false, true, false),
            ],
        );
        assert!(waiting_of(g(), &ok).is_empty());
        assert!(waiting_notices(g(), &waiting_of(g(), &ok)).is_empty());
        // Many names are cut short.
        let many: Vec<String> = (0..5).map(|i| format!("n{i}")).collect();
        let n = waiting_notices(
            g(),
            &Waiting {
                invited: many,
                ..Waiting::default()
            },
        );
        assert!(n[0].1.contains("n0, n1, n2 +2"));
    }

    #[test]
    fn the_system_line_says_who_added_me() {
        let mut d = detail(
            "joined",
            false,
            vec![
                member("me", true, false, false),
                member("amy", false, true, true),
            ],
        );
        assert_eq!(added_by_line(g(), &d), None);
        d.added_by = Some("amy".into());
        assert_eq!(
            added_by_line(g(), &d).as_deref(),
            Some("You were added by label amy")
        );
        d.added_by = Some("someone gone".into());
        assert_eq!(
            added_by_line(g(), &d).as_deref(),
            Some("You were added to this group")
        );
        for lang in crate::locale::Locale::ALL {
            let s = crate::locale::group_strings(lang);
            assert!(s.added_by.contains("{who}"), "{lang:?}");
        }
    }

    #[test]
    fn invitations_are_listed_with_who_invited_and_counted_for_the_navigation() {
        let mut list = vec![
            info("g1", "joined", 3, 5, 10),
            info("g2", "invited", 3, 0, 20),
            info("g3", "invited", 2, 0, 30),
        ];
        list[1].invited_by = Some("amy".into());
        let rows = group_rows(&list);
        let inv = invitations(&rows);
        assert_eq!(
            inv.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["g2", "g3"]
        );
        let contacts = [contact("c-amy", "amy", true)];
        assert_eq!(inviter_name(g(), &contacts, inv[0]), "Contact c-amy");
        assert_eq!(inviter_name(g(), &contacts, inv[1]), "A contact");
        assert_eq!(inviter_name(g(), &[], inv[0]), "A contact");
        // The navigation announces an invitation once, on the first list too, until it is answered.
        let mut u = GroupUnread::default();
        u.on_list(&rows, None, false);
        assert_eq!(u.unseen(), 2);
        u.on_list(&rows, None, false);
        assert_eq!(u.unseen(), 2, "not counted again");
        u.mark_seen();
        let mut more = list.clone();
        more.push(info("g4", "invited", 2, 0, 40));
        u.on_list(&group_rows(&more), None, false);
        assert_eq!(u.unseen(), 1, "a new invitation is news");
        // Every invitation has a badge on its row.
        assert_eq!(u.of(&rows[1]), 1);
    }

    #[test]
    fn the_join_setting_is_read_and_saved_in_the_configuration_file() {
        let dir = tempfile::tempdir().unwrap();
        // Nothing saved yet: on.
        assert!(load_auto_join(dir.path()));
        for on in [false, true, false] {
            save_auto_join(dir.path(), on).unwrap();
            assert_eq!(load_auto_join(dir.path()), on);
            // The same key the command line reads.
            let c = NodeConfig::load(dir.path()).unwrap();
            assert_eq!(c.chat.group_auto_join, on);
        }
    }

    #[test]
    fn warning_and_status_colours_used_here_are_readable() {
        // The unverified badge is warning-coloured text on the incoming bubble (surface); the
        // delivery lines use success, danger and muted on the window background.
        for (name, p) in [("light", Palette::light()), ("dark", Palette::dark())] {
            for (tok, c, bg_name, bg) in [
                ("warning", p.warning, "surface", p.surface),
                ("warning", p.warning, "bg", p.bg),
                ("muted", p.muted, "surface", p.surface),
                ("success", p.success, "bg", p.bg),
                ("danger", p.danger, "bg", p.bg),
                ("text", p.text, "selected", p.selected),
            ] {
                let r = contrast(c, bg);
                assert!(r >= 4.5, "{name}: {tok} on {bg_name} = {r:.2}");
            }
        }
    }
}
