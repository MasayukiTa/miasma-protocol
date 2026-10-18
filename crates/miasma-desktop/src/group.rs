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
        }
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
}

impl GroupUnread {
    /// A fresh list of groups arrived. `viewing` is the group on screen with the tab open.
    pub fn on_list(&mut self, rows: &[GroupRow], viewing: Option<&str>, area_open: bool) {
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

/// The line under a member's name: role and the verified marker, for the screen reader too.
pub fn member_summary(g: &GroupStrings, m: &MemberInfo) -> String {
    let role = if m.role == "admin" {
        g.role_admin
    } else {
        g.role_member
    };
    let state = if m.you {
        g.you_tag
    } else if m.verified {
        g.marker_verified
    } else {
        g.marker_unverified
    };
    fill(
        g.a11y_member,
        &[
            ("name", &member_name(g, m)),
            ("role", role),
            ("state", state),
        ],
    )
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
    NoMembers,
    TooMany,
}

/// The new-group form.
#[derive(Debug, Default, Clone)]
pub struct NewGroupForm {
    pub name: String,
    pub picks: Picks,
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
        cap_text(&mut self.name, MAX_NAME_BYTES);
        if self.error == Some(FormError::Name) {
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
        let mut name = name.to_owned();
        cap_text(&mut name, MAX_NAME_BYTES);
        Ok((name, self.picks.ids().to_vec()))
    }
}

pub fn form_error_text(g: &GroupStrings, e: FormError) -> String {
    match e {
        FormError::Name => g.ng_err_name.to_owned(),
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
    let tail = match row.status {
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
    };
    if tail.is_empty() {
        members
    } else {
        format!("{members} | {tail}")
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
        }
    }

    fn detail(status: &str, is_admin: bool, members: Vec<MemberInfo>) -> GroupDetailInfo {
        GroupDetailInfo {
            group: info("1", status, members.len() as u32, 0, 0),
            members,
            is_admin,
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
        // A very long name is cut on a character boundary.
        f.name = "あ".repeat(200);
        f.edit_name();
        assert!(f.name.len() <= MAX_NAME_BYTES);
        assert!(f.check().is_ok());
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
        assert_eq!(u.unseen(), 0, "a group appearing is not a message");
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
