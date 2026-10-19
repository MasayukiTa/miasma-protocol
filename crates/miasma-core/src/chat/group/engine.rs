//! The group engine without the network: membership changes, sending,
//! receiving and the bookkeeping of who still owes whom what. The service
//! feeds it connections; the tests feed it directly.
//!
//! **Delivery** is pairwise. A message is not encrypted once for the group:
//! for every member it is sealed again on the pairwise session this device
//! already has with that member (the session of the private conversation, or
//! one started from the two endpoint IDs), so the cipher, forward secrecy and
//! replay protection are those of the private chat. The record carries the
//! group ID, the membership epoch and a counter of the sender in that group.
//!
//! **Order and duplicates.** Each sender numbers its group messages 1, 2, ...
//! A receiver keeps, per sender, the vector of applied counters
//! ([`SenderVec`]): a counter is applied once, out-of-order arrival is fine,
//! and a hole is visible as a gap. Messages are shown ordered by send time
//! with each sender's own counter order preserved.
//!
//! **Trust.** Being listed in a group makes nobody a contact. A member who is
//! not a trusted contact is shown as unverified, may only send short text
//! inside the group, and gets no file or private-chat permission from it. The
//! contact list is never changed from here.
//!
//! **Removal.** After a change the sender stops sending to members that are no
//! longer listed, their undelivered copies are dropped, and receivers refuse
//! group records from anyone the newest descriptor does not list. The removed
//! member is still sent the descriptor that removes it, nothing else.
//!
//! Lock order: the chat gate (inside [`ChatCore`]) is taken before `inner`,
//! never the other way round; no method here holds `inner` while it seals.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use ed25519_dalek::SigningKey;
use tracing::{debug, warn};

use super::{
    membership::{
        Chain, DescError, Descriptor, Member, Role, MAX_HINT_BYTES, MAX_MEMBERS, MAX_NAME_BYTES,
    },
    record::{self, GroupText, Record},
    state::{CtrlKind, GroupState, LedgerEntry, PendingMsg, Status, MAX_PENDING},
    store::{GroupMsg, GroupStore},
};
use crate::chat::{engine::ChatCore, proto::AckStatus};

/// Groups on one device, whatever their status.
pub const MAX_GROUPS: usize = 32;
/// Invitations waiting for an answer.
pub const MAX_INVITES: usize = 8;
/// Largest text a member who is not a trusted contact may send.
pub const UNVERIFIED_MAX_TEXT: usize = 2048;
const EVENT_CAP: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GroupError {
    #[error("the message is empty")]
    Empty,
    #[error("the message is too long")]
    TooBig,
    #[error("no such group")]
    NotFound,
    #[error("ambiguous group")]
    Ambiguous,
    #[error("you have not joined this group")]
    NotJoined,
    #[error("only an admin may do this")]
    NotAdmin,
    #[error("that person is not in the group")]
    NotMember,
    #[error("that person is already in the group")]
    AlreadyMember,
    #[error("this device holds the most groups it can")]
    TooManyGroups,
    #[error("a group holds at most {MAX_MEMBERS} members")]
    TooManyMembers,
    #[error("the last admin cannot leave; make someone else an admin first")]
    LastAdmin,
    #[error("too many messages are waiting to be delivered in this group")]
    QueueFull,
    #[error("invalid group name or member")]
    Invalid,
    #[error("{0}")]
    Storage(String),
}

impl From<DescError> for GroupError {
    fn from(e: DescError) -> Self {
        match e {
            DescError::TooManyMembers => GroupError::TooManyMembers,
            DescError::NoAdmin => GroupError::LastAdmin,
            DescError::NotAuthorized => GroupError::NotAdmin,
            _ => GroupError::Invalid,
        }
    }
}

impl From<crate::chat::store::StoreError> for GroupError {
    fn from(e: crate::chat::store::StoreError) -> Self {
        GroupError::Storage(e.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupEventKind {
    /// A message arrived.
    Received,
    /// We were invited into a group and wait for an answer.
    Invited,
    /// We were added to a group and joined at once (auto-join).
    Joined,
    /// The member list or our standing changed.
    Changed,
}

#[derive(Debug, Clone)]
pub struct GroupEvent {
    pub seq: u64,
    pub gid: [u8; 16],
    pub kind: GroupEventKind,
    pub message: Option<GroupMsg>,
}

/// One thing to put on the wire for a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Work {
    Text { gid: [u8; 16], id: [u8; 16] },
    Descs { gid: [u8; 16] },
    Sync { gid: [u8; 16] },
}

#[derive(Debug, Clone)]
pub struct Outgoing {
    pub work: Work,
    pub plain: Vec<u8>,
}

/// What a received envelope led to.
#[derive(Debug, Clone)]
pub struct Accepted {
    pub status: AckStatus,
    /// Members that now have something waiting for them.
    pub kick: Vec<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct SendOutcome {
    pub id: [u8; 16],
    pub recipients: Vec<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct GroupSummary {
    pub gid: [u8; 16],
    pub name: String,
    pub epoch: u32,
    pub status: Status,
    pub members: usize,
    pub messages: u64,
    pub last_ms: u64,
    /// Copies of our messages still owed to members.
    pub pending: usize,
}

/// What this device knows about one member being in the group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberStatus {
    /// This device.
    You,
    /// The member has shown it is in the group.
    Joined,
    /// Listed, but nothing has shown yet that the member joined: it has not
    /// answered an invitation, or has not been online since.
    Invited,
    /// Our last attempt to reach the member failed; the word says how
    /// (`no_route`, `connect_failed`, `send_disabled`, ...).
    Unreachable(String),
    /// The member's Miasma has no group chat: it must be updated.
    NoGroupSupport,
}

impl MemberStatus {
    /// A stable word for IPC and logs.
    pub fn name(&self) -> &'static str {
        match self {
            MemberStatus::You => "you",
            MemberStatus::Joined => "joined",
            MemberStatus::Invited => "invited",
            MemberStatus::Unreachable(_) => "unreachable",
            MemberStatus::NoGroupSupport => "no_group_support",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MemberView {
    pub id: [u8; 32],
    pub role: Role,
    pub hint: String,
    /// A trusted contact of this device.
    pub verified: bool,
    pub you: bool,
    pub status: MemberStatus,
}

#[derive(Debug, Clone)]
pub struct GroupDetail {
    pub summary: GroupSummary,
    pub members: Vec<MemberView>,
    pub is_admin: bool,
    pub my_counter: u64,
    /// Who added us, when we joined through an invitation.
    pub added_by: Option<[u8; 32]>,
}

/// The delivery failure words that mean the member's software has no group
/// chat (see [`crate::chat::proto::fail`]).
fn means_no_group_support(reason: &str) -> bool {
    reason == crate::chat::proto::fail::PEER_NO_GROUP
        || reason == crate::chat::proto::fail::UNSUPPORTED
}

#[derive(Debug, Clone)]
pub struct MessageView {
    pub msg: GroupMsg,
    /// For our own messages: (total, delivered, failed) while the ledger still
    /// holds the message.
    pub delivery: Option<(u8, u8, u8)>,
    /// Counters of this sender below this one that never arrived.
    pub gap_before: u64,
}

struct Events {
    next: u64,
    items: VecDeque<GroupEvent>,
}

struct Inner {
    groups: BTreeMap<[u8; 16], GroupState>,
    events: Events,
    /// Why the last attempt to deliver to a member failed (memory only; a
    /// success removes the entry).
    reasons: HashMap<[u8; 32], String>,
}

pub struct GroupCore {
    chat: Arc<ChatCore>,
    key: SigningKey,
    own: [u8; 32],
    store: GroupStore,
    max_text: usize,
    /// Join at once when a trusted administrator adds us (`chat.group_auto_join`).
    auto_join: AtomicBool,
    inner: Mutex<Inner>,
}

fn trim_hint(h: &str) -> String {
    let h = h.trim();
    let mut end = h.len().min(MAX_HINT_BYTES);
    while !h.is_char_boundary(end) {
        end -= 1;
    }
    h[..end].to_owned()
}

impl GroupCore {
    /// `seed` is the Ed25519 seed of the identity `chat` runs with.
    pub fn new(chat: Arc<ChatCore>, store: GroupStore, seed: &[u8; 32]) -> Option<Self> {
        let key = SigningKey::from_bytes(seed);
        let own = key.verifying_key().to_bytes();
        if own != chat.own_id() {
            warn!("group chat stays off: its identity differs from the chat's");
            return None;
        }
        let mut groups = BTreeMap::new();
        for s in store.load_all() {
            groups.insert(s.gid(), s);
        }
        let max_text = chat.max_text();
        Some(Self {
            chat,
            key,
            own,
            store,
            max_text,
            auto_join: AtomicBool::new(true),
            inner: Mutex::new(Inner {
                groups,
                events: Events {
                    next: 1,
                    items: VecDeque::new(),
                },
                reasons: HashMap::new(),
            }),
        })
    }

    /// Whether an invitation from a trusted administrator makes us a member
    /// at once (the default) instead of waiting for an answer.
    pub fn auto_join(&self) -> bool {
        self.auto_join.load(Ordering::Relaxed)
    }

    /// Applies to invitations that arrive from now on; invitations already
    /// waiting keep waiting.
    pub fn set_auto_join(&self, on: bool) {
        self.auto_join.store(on, Ordering::Relaxed);
    }

    /// The delivery worker's last word about `peer`: `Some(reason)` after a
    /// failed or refused attempt, `None` after a success.
    pub fn note_delivery(&self, peer: &[u8; 32], reason: Option<&str>) {
        let mut g = self.lock();
        match reason {
            Some(r) => {
                if g.reasons.len() < 4 * MAX_MEMBERS || g.reasons.contains_key(peer) {
                    g.reasons.insert(*peer, r.to_owned());
                }
            }
            None => {
                g.reasons.remove(peer);
            }
        }
    }

    pub fn own_id(&self) -> [u8; 32] {
        self.own
    }

    pub fn chat(&self) -> &Arc<ChatCore> {
        &self.chat
    }

    pub fn store(&self) -> &GroupStore {
        &self.store
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self, st: &GroupState) -> Result<(), GroupError> {
        Ok(self.store.write_state(st)?)
    }

    fn push_event(inner: &mut Inner, gid: [u8; 16], kind: GroupEventKind, m: Option<GroupMsg>) {
        let e = &mut inner.events;
        let seq = e.next;
        e.next += 1;
        if e.items.len() >= EVENT_CAP {
            e.items.pop_front();
        }
        e.items.push_back(GroupEvent {
            seq,
            gid,
            kind,
            message: m,
        });
    }

    pub fn events_since(&self, since: u64) -> (u64, Vec<GroupEvent>) {
        let g = self.lock();
        (
            g.events.next - 1,
            g.events
                .items
                .iter()
                .filter(|x| x.seq > since)
                .cloned()
                .collect(),
        )
    }

    // ── Lookup ───────────────────────────────────────────────────────────────

    /// A group by ID prefix (4 or more hex digits) or by exact name.
    pub fn resolve(&self, sel: &str) -> Result<[u8; 16], GroupError> {
        let sel = sel.trim();
        let g = self.lock();
        let lower = sel.to_ascii_lowercase();
        if lower.len() >= 4 && lower.chars().all(|c| c.is_ascii_hexdigit()) {
            let hits: Vec<[u8; 16]> = g
                .groups
                .keys()
                .filter(|k| hex::encode(k).starts_with(&lower))
                .copied()
                .collect();
            match hits.len() {
                1 => return Ok(hits[0]),
                n if n > 1 => return Err(GroupError::Ambiguous),
                _ => {}
            }
        }
        let hits: Vec<[u8; 16]> = g
            .groups
            .iter()
            .filter(|(_, s)| s.name().eq_ignore_ascii_case(sel))
            .map(|(k, _)| *k)
            .collect();
        match hits.len() {
            0 => Err(GroupError::NotFound),
            1 => Ok(hits[0]),
            _ => Err(GroupError::Ambiguous),
        }
    }

    fn summary_of(st: &GroupState) -> GroupSummary {
        GroupSummary {
            gid: st.gid(),
            name: st.name().to_owned(),
            epoch: st.chain.epoch(),
            status: st.status,
            members: st.chain.latest().members.len(),
            messages: st.count,
            last_ms: st.last_ms,
            pending: st.pending.iter().map(|p| p.to.len()).sum(),
        }
    }

    pub fn list(&self) -> Vec<GroupSummary> {
        let g = self.lock();
        let mut v: Vec<GroupSummary> = g.groups.values().map(Self::summary_of).collect();
        v.sort_by(|a, b| b.last_ms.cmp(&a.last_ms).then(a.name.cmp(&b.name)));
        v
    }

    pub fn detail(
        &self,
        gid: &[u8; 16],
        trusted: &dyn Fn(&[u8; 32]) -> bool,
    ) -> Result<GroupDetail, GroupError> {
        let g = self.lock();
        let st = g.groups.get(gid).ok_or(GroupError::NotFound)?;
        let latest = st.chain.latest();
        Ok(GroupDetail {
            summary: Self::summary_of(st),
            members: latest
                .members
                .iter()
                .map(|m| MemberView {
                    id: m.id,
                    role: m.role,
                    hint: m.hint.clone(),
                    verified: m.id != self.own && trusted(&m.id),
                    you: m.id == self.own,
                    status: self.member_status(&g, st, &m.id),
                })
                .collect(),
            is_admin: latest.is_admin(&self.own),
            my_counter: st.my_counter,
            added_by: st.added_by,
        })
    }

    fn member_status(&self, g: &Inner, st: &GroupState, id: &[u8; 32]) -> MemberStatus {
        if *id == self.own {
            return MemberStatus::You;
        }
        // A member that has shown it is in the group stays joined, whatever
        // the network does later.
        if st.confirmed.contains(id) || st.vectors.contains_key(id) {
            return MemberStatus::Joined;
        }
        match g.reasons.get(id) {
            Some(r) if means_no_group_support(r) => MemberStatus::NoGroupSupport,
            Some(r) => MemberStatus::Unreachable(r.clone()),
            None => MemberStatus::Invited,
        }
    }

    /// The members listed now (empty for an unknown group).
    pub fn members_of(&self, gid: &[u8; 16]) -> Vec<[u8; 32]> {
        let g = self.lock();
        g.groups
            .get(gid)
            .map(|s| s.chain.latest().members.iter().map(|m| m.id).collect())
            .unwrap_or_default()
    }

    /// The newest descriptor we hold for a group.
    pub fn latest_descriptor(&self, gid: &[u8; 16]) -> Option<Descriptor> {
        self.lock()
            .groups
            .get(gid)
            .map(|s| s.chain.latest().clone())
    }

    pub fn status_of(&self, gid: &[u8; 16]) -> Option<Status> {
        self.lock().groups.get(gid).map(|s| s.status)
    }

    /// Whether `peer` appears in any group we hold.
    pub fn knows(&self, peer: &[u8; 32]) -> bool {
        self.lock()
            .groups
            .values()
            .any(|s| s.chain.ever_member(peer))
    }

    /// Per-sender vector of a group: (floor, highest, missing).
    pub fn vector_of(&self, gid: &[u8; 16], sender: &[u8; 32]) -> Option<(u64, u64, u64)> {
        let g = self.lock();
        let v = g.groups.get(gid)?.vectors.get(sender)?;
        Some((v.floor, v.highest(), v.missing()))
    }

    /// Members with something waiting for them.
    pub fn peers_with_work(&self) -> Vec<[u8; 32]> {
        let g = self.lock();
        let mut out: Vec<[u8; 32]> = Vec::new();
        for st in g.groups.values() {
            for c in &st.ctrl {
                out.push(c.to);
            }
            for p in &st.pending {
                out.extend(p.to.iter().copied());
            }
        }
        out.sort();
        out.dedup();
        out
    }

    // ── Changing a group ─────────────────────────────────────────────────────

    fn live_group<'a>(
        inner: &'a mut Inner,
        gid: &[u8; 16],
    ) -> Result<&'a mut GroupState, GroupError> {
        let st = inner.groups.get_mut(gid).ok_or(GroupError::NotFound)?;
        if st.status != Status::Joined {
            return Err(GroupError::NotJoined);
        }
        Ok(st)
    }

    /// Create a group with `members` (other people; `(endpoint id, label)`).
    /// Returns the group ID.
    pub fn create(
        &self,
        name: &str,
        members: &[([u8; 32], String)],
        now: u64,
    ) -> Result<[u8; 16], GroupError> {
        let name = name.trim();
        if name.is_empty() || name.len() > MAX_NAME_BYTES {
            return Err(GroupError::Invalid);
        }
        if members.len() + 1 > MAX_MEMBERS {
            return Err(GroupError::TooManyMembers);
        }
        let mut list = vec![Member {
            id: self.own,
            role: Role::Admin,
            hint: String::new(),
        }];
        for (id, hint) in members {
            if *id == self.own || list.iter().any(|m| &m.id == id) {
                return Err(GroupError::Invalid);
            }
            list.push(Member {
                id: *id,
                role: Role::Member,
                hint: trim_hint(hint),
            });
        }
        let gid: [u8; 16] = rand::random();
        let d = Descriptor {
            gid,
            epoch: 1,
            name: name.to_owned(),
            created_ms: now,
            prev_hash: [0; 32],
            members: list,
            signer: [0; 32],
            sig: [0; 64],
        }
        .signed(&self.key);
        let chain = Chain::from_root(d)?;
        let mut st = GroupState::new(chain, Status::Joined);
        st.last_ms = now;
        for m in &st.chain.latest().members.clone() {
            if m.id != self.own {
                st.owe(m.id, CtrlKind::Descs, 0);
            }
        }
        let mut g = self.lock();
        if g.groups.len() >= MAX_GROUPS {
            return Err(GroupError::TooManyGroups);
        }
        self.save(&st)?;
        g.groups.insert(gid, st);
        Ok(gid)
    }

    fn next_descriptor(prev: &Descriptor, members: Vec<Member>, key: &SigningKey) -> Descriptor {
        Descriptor {
            gid: prev.gid,
            epoch: prev.epoch + 1,
            name: prev.name.clone(),
            created_ms: prev.created_ms,
            prev_hash: prev.hash(),
            members,
            signer: [0; 32],
            sig: [0; 64],
        }
        .signed(key)
    }

    /// Add people (`(endpoint id, label, as admin)`). Admin only.
    pub fn add(
        &self,
        gid: &[u8; 16],
        new: &[([u8; 32], String, bool)],
    ) -> Result<Vec<[u8; 32]>, GroupError> {
        let mut g = self.lock();
        let st = Self::live_group(&mut g, gid)?;
        let latest = st.chain.latest().clone();
        if !latest.is_admin(&self.own) {
            return Err(GroupError::NotAdmin);
        }
        if latest.members.len() + new.len() > MAX_MEMBERS {
            return Err(GroupError::TooManyMembers);
        }
        let mut members = latest.members.clone();
        for (id, hint, admin) in new {
            if members.iter().any(|m| &m.id == id) {
                return Err(GroupError::AlreadyMember);
            }
            members.push(Member {
                id: *id,
                role: if *admin { Role::Admin } else { Role::Member },
                hint: trim_hint(hint),
            });
        }
        let d = Self::next_descriptor(&latest, members, &self.key);
        st.chain.push(d)?;
        let others: Vec<[u8; 32]> = st
            .chain
            .latest()
            .members
            .iter()
            .map(|m| m.id)
            .filter(|id| *id != self.own)
            .collect();
        for o in &others {
            st.owe(*o, CtrlKind::Descs, 0);
        }
        self.save(st)?;
        Self::push_event(&mut g, *gid, GroupEventKind::Changed, None);
        Ok(others)
    }

    /// Remove a member. Admin only; use [`leave`](Self::leave) for yourself.
    /// Returns the people to notify (the remaining members and the removed one).
    pub fn remove(&self, gid: &[u8; 16], who: &[u8; 32]) -> Result<Vec<[u8; 32]>, GroupError> {
        let mut g = self.lock();
        let st = Self::live_group(&mut g, gid)?;
        let latest = st.chain.latest().clone();
        if !latest.is_admin(&self.own) {
            return Err(GroupError::NotAdmin);
        }
        if *who == self.own {
            return Err(GroupError::Invalid);
        }
        if !latest.is_member(who) {
            return Err(GroupError::NotMember);
        }
        let members: Vec<Member> = latest
            .members
            .iter()
            .filter(|m| &m.id != who)
            .cloned()
            .collect();
        let d = Self::next_descriptor(&latest, members, &self.key);
        st.chain.push(d)?;
        Self::prune(st);
        let mut notify: Vec<[u8; 32]> = st
            .chain
            .latest()
            .members
            .iter()
            .map(|m| m.id)
            .filter(|id| *id != self.own)
            .collect();
        notify.push(*who);
        for o in &notify {
            st.owe(*o, CtrlKind::Descs, 0);
        }
        self.save(st)?;
        Self::push_event(&mut g, *gid, GroupEventKind::Changed, None);
        Ok(notify)
    }

    /// Leave a group with a descriptor signed by ourselves. The people who
    /// remain are told. The state stays on this device (with the history)
    /// until [`forget`](Self::forget).
    pub fn leave(&self, gid: &[u8; 16]) -> Result<Vec<[u8; 32]>, GroupError> {
        let mut g = self.lock();
        let st = Self::live_group(&mut g, gid)?;
        let latest = st.chain.latest().clone();
        let members: Vec<Member> = latest
            .members
            .iter()
            .filter(|m| m.id != self.own)
            .cloned()
            .collect();
        let others: Vec<[u8; 32]> = members.iter().map(|m| m.id).collect();
        if members.is_empty() {
            // Alone in the group: nothing to tell anyone.
            st.status = Status::Left;
            self.save(st)?;
            return Ok(others);
        }
        if latest.is_admin(&self.own) && !members.iter().any(|m| m.role == Role::Admin) {
            return Err(GroupError::LastAdmin);
        }
        let d = Self::next_descriptor(&latest, members, &self.key);
        st.chain.push(d)?;
        st.status = Status::Left;
        for o in &others {
            st.owe(*o, CtrlKind::Descs, 0);
        }
        self.save(st)?;
        Self::push_event(&mut g, *gid, GroupEventKind::Changed, None);
        Ok(others)
    }

    /// Answer an invitation with yes. Returns the members to wake: each is
    /// owed a request for the newest descriptors, which is also how they learn
    /// that we joined (a device that has not joined refuses it).
    pub fn accept_invite(&self, gid: &[u8; 16]) -> Result<Vec<[u8; 32]>, GroupError> {
        let mut g = self.lock();
        let st = g.groups.get_mut(gid).ok_or(GroupError::NotFound)?;
        match st.status {
            Status::Pending { invited_by } => {
                let others = Self::become_member(st, self.own, invited_by);
                self.save(st)?;
                Self::push_event(&mut g, *gid, GroupEventKind::Changed, None);
                Ok(others)
            }
            Status::Joined => Ok(Vec::new()),
            _ => Err(GroupError::NotJoined),
        }
    }

    /// We are in the group now, added by `by`: remember who, and owe each of
    /// the others a sync request so they (and the person who added us) see
    /// that we joined and we see that they did.
    fn become_member(st: &mut GroupState, own: [u8; 32], by: [u8; 32]) -> Vec<[u8; 32]> {
        st.status = Status::Joined;
        st.added_by = Some(by);
        let epoch = st.chain.epoch();
        let others: Vec<[u8; 32]> = st
            .chain
            .latest()
            .members
            .iter()
            .map(|m| m.id)
            .filter(|id| *id != own)
            .collect();
        for o in &others {
            st.owe(*o, CtrlKind::Sync, epoch);
        }
        others
    }

    /// Decline an invitation, or drop a group we left or were removed from:
    /// every file of it is deleted from this device.
    pub fn forget(&self, gid: &[u8; 16]) -> Result<(), GroupError> {
        let mut g = self.lock();
        let st = g.groups.get(gid).ok_or(GroupError::NotFound)?;
        if st.status == Status::Joined {
            return Err(GroupError::Invalid);
        }
        self.store.delete_group(gid)?;
        g.groups.remove(gid);
        Ok(())
    }

    /// After a member list shrank: stop owing copies to people who are gone.
    fn prune(st: &mut GroupState) {
        let listed: Vec<[u8; 32]> = st.chain.latest().members.iter().map(|m| m.id).collect();
        let mut dropped: Vec<([u8; 16], u8)> = Vec::new();
        for p in &mut st.pending {
            let before = p.to.len();
            p.to.retain(|t| listed.contains(t));
            let gone = (before - p.to.len()) as u8;
            if gone > 0 {
                dropped.push((p.id, gone));
            }
        }
        st.pending.retain(|p| !p.to.is_empty());
        for (id, n) in dropped {
            if let Some(l) = st.ledger_mut(&id) {
                l.failed = l.failed.saturating_add(n);
            }
        }
        st.ctrl.retain(|c| listed.contains(&c.to));
    }

    // ── Sending ──────────────────────────────────────────────────────────────

    /// Accept a message for the group: number it, keep it for every member
    /// and write it to our own history. The caller wakes the delivery.
    pub fn send(&self, gid: &[u8; 16], text: &str, now: u64) -> Result<SendOutcome, GroupError> {
        if text.is_empty() {
            return Err(GroupError::Empty);
        }
        if text.len() > self.max_text {
            return Err(GroupError::TooBig);
        }
        let mut g = self.lock();
        let st = Self::live_group(&mut g, gid)?;
        if st.pending.len() >= MAX_PENDING {
            return Err(GroupError::QueueFull);
        }
        let latest = st.chain.latest();
        let recipients: Vec<[u8; 32]> = latest
            .members
            .iter()
            .map(|m| m.id)
            .filter(|id| *id != self.own)
            .collect();
        let epoch = latest.epoch;
        st.my_counter += 1;
        let counter = st.my_counter;
        let id: [u8; 16] = rand::random();
        // The counter is on disk before anything is sent.
        if !recipients.is_empty() {
            st.pending.push(PendingMsg {
                id,
                counter,
                epoch,
                sent_ms: now,
                text: text.to_owned(),
                to: recipients.clone(),
            });
            st.push_ledger(LedgerEntry {
                id,
                total: recipients.len() as u8,
                delivered: 0,
                failed: 0,
            });
        }
        self.record_locked(
            st,
            GroupMsg {
                ord: 0,
                outgoing: true,
                sender: self.own,
                counter,
                id,
                sent_ms: now,
                at_ms: now,
                epoch,
                text: text.to_owned(),
            },
        )?;
        self.save(st)?;
        Ok(SendOutcome { id, recipients })
    }

    fn record_locked(&self, st: &mut GroupState, mut m: GroupMsg) -> Result<(), GroupError> {
        let gid = st.gid();
        if st.next_ord == 0 {
            let (max, n) = self.store.max_ord(&gid);
            st.next_ord = max + 1;
            st.count = n;
        }
        m.ord = st.next_ord;
        st.next_ord += 1;
        st.count += 1;
        st.last_ms = st.last_ms.max(m.at_ms);
        self.store.record(&gid, m, true, st.count)?;
        Ok(())
    }

    /// The next item owed to `peer`, with its plaintext. Descriptors and
    /// requests go before messages, so the receiver knows the epoch first.
    pub fn next_for(&self, peer: &[u8; 32]) -> Option<Outgoing> {
        let g = self.lock();
        for st in g.groups.values() {
            if let Some(c) = st.ctrl.iter().find(|c| &c.to == peer) {
                let gid = st.gid();
                return match c.kind {
                    CtrlKind::Descs => {
                        let fit = record::newest_that_fit(st.chain.items());
                        record::encode_descs(&fit).ok().map(|plain| Outgoing {
                            work: Work::Descs { gid },
                            plain,
                        })
                    }
                    CtrlKind::Sync => Some(Outgoing {
                        work: Work::Sync { gid },
                        plain: record::encode_sync(&gid, c.arg),
                    }),
                };
            }
        }
        for st in g.groups.values() {
            let hit = st
                .pending
                .iter()
                .filter(|p| p.to.contains(peer))
                .min_by_key(|p| p.counter);
            if let Some(p) = hit {
                let gid = st.gid();
                let plain = GroupText {
                    gid,
                    epoch: p.epoch,
                    counter: p.counter,
                    id: p.id,
                    sent_ms: p.sent_ms,
                    text: p.text.clone(),
                }
                .encode()
                .ok()?;
                return Some(Outgoing {
                    work: Work::Text { gid, id: p.id },
                    plain,
                });
            }
        }
        None
    }

    fn settle(&self, peer: &[u8; 32], work: &Work, delivered: bool) {
        let mut g = self.lock();
        let gid = match work {
            Work::Text { gid, .. } | Work::Descs { gid } | Work::Sync { gid } => *gid,
        };
        let Some(st) = g.groups.get_mut(&gid) else {
            return;
        };
        match work {
            Work::Descs { .. } => st
                .ctrl
                .retain(|c| !(&c.to == peer && c.kind == CtrlKind::Descs)),
            Work::Sync { .. } => st
                .ctrl
                .retain(|c| !(&c.to == peer && c.kind == CtrlKind::Sync)),
            Work::Text { id, .. } => {
                if let Some(p) = st.pending.iter_mut().find(|p| &p.id == id) {
                    p.to.retain(|t| t != peer);
                }
                st.pending.retain(|p| !p.to.is_empty());
                if delivered {
                    // A device that has not joined answers "busy": an accepted
                    // text means the member is in the group.
                    st.confirm(peer);
                }
                if let Some(l) = st.ledger_mut(id) {
                    if delivered {
                        l.delivered = l.delivered.saturating_add(1);
                    } else {
                        l.failed = l.failed.saturating_add(1);
                    }
                }
            }
        }
        if let Err(e) = self.save(st) {
            warn!("a group state could not be written: {e}");
        }
    }

    /// The member acknowledged the item.
    pub fn delivered(&self, peer: &[u8; 32], work: &Work) {
        self.settle(peer, work, true);
    }

    /// The item will not be delivered to this member (they refuse it).
    pub fn gave_up(&self, peer: &[u8; 32], work: &Work) {
        self.settle(peer, work, false);
    }

    // ── Receiving ────────────────────────────────────────────────────────────

    /// Apply an envelope from `peer` (authenticated by the transport).
    /// `trusted` says whether an ID is a trusted contact of this device.
    pub fn accept(
        &self,
        peer: &[u8; 32],
        wire: &[u8],
        now: u64,
        trusted: &dyn Fn(&[u8; 32]) -> bool,
    ) -> Accepted {
        let mut kick = Vec::new();
        let status = self.chat.accept_raw(peer, wire, |plain| {
            self.handle(peer, plain, now, trusted, &mut kick)
        });
        Accepted { status, kick }
    }

    fn handle(
        &self,
        peer: &[u8; 32],
        plain: &[u8],
        now: u64,
        trusted: &dyn Fn(&[u8; 32]) -> bool,
        kick: &mut Vec<[u8; 32]>,
    ) -> AckStatus {
        let rec = match Record::decode(plain) {
            Ok(r) => r,
            Err(record::RecordError::UnknownKind(_)) => return AckStatus::Unsupported,
            Err(_) => return AckStatus::BadRequest,
        };
        let mut g = self.lock();
        match rec {
            Record::Text(t) => self.handle_text(&mut g, peer, t, now, trusted, kick),
            Record::Descs(ds) => self.handle_descs(&mut g, peer, ds, now, trusted, kick),
            Record::Sync { gid, .. } => {
                let Some(st) = g.groups.get_mut(&gid) else {
                    return AckStatus::NotAllowed;
                };
                if !st.chain.ever_member(peer) {
                    return AckStatus::NotAllowed;
                }
                if matches!(st.status, Status::Pending { .. }) {
                    return AckStatus::Busy;
                }
                // Only a device that joined asks for descriptors.
                let news = st.chain.latest().is_member(peer) && st.confirm(peer);
                let owed = st.owe(*peer, CtrlKind::Descs, 0);
                if owed {
                    kick.push(*peer);
                }
                if (owed || news) && self.save(st).is_err() {
                    return AckStatus::Failed;
                }
                AckStatus::Stored
            }
        }
    }

    fn handle_text(
        &self,
        g: &mut Inner,
        peer: &[u8; 32],
        t: GroupText,
        now: u64,
        trusted: &dyn Fn(&[u8; 32]) -> bool,
        kick: &mut Vec<[u8; 32]>,
    ) -> AckStatus {
        let Some(st) = g.groups.get_mut(&t.gid) else {
            return AckStatus::NotAllowed;
        };
        match st.status {
            Status::Pending { .. } => return AckStatus::Busy,
            Status::Left | Status::Removed => return AckStatus::NotAllowed,
            Status::Joined => {}
        }
        let cur = st.chain.epoch();
        if t.epoch > cur {
            // The sender is ahead of us: ask for what we are missing and let
            // it try again afterwards.
            if st.owe(*peer, CtrlKind::Sync, cur) {
                kick.push(*peer);
                let _ = self.save(st);
            }
            return AckStatus::Busy;
        }
        // Only people the newest descriptor lists may write; a removed member
        // cannot slip messages in under an older epoch number.
        if !st.chain.latest().is_member(peer) {
            return AckStatus::NotAllowed;
        }
        if t.text.len() > self.max_text || (!trusted(peer) && t.text.len() > UNVERIFIED_MAX_TEXT) {
            return AckStatus::TooBig;
        }
        if !st.vectors.get(peer).is_none_or(|v| v.is_new(t.counter)) {
            return AckStatus::Duplicate;
        }
        if !st.vectors.contains_key(peer) && st.vectors.len() >= super::state::MAX_VECTORS {
            return AckStatus::Busy;
        }
        let m = GroupMsg {
            ord: 0,
            outgoing: false,
            sender: *peer,
            counter: t.counter,
            id: t.id,
            sent_ms: t.sent_ms,
            at_ms: now,
            epoch: t.epoch,
            text: t.text,
        };
        let before = (st.next_ord, st.count, st.last_ms);
        if self.record_locked(st, m.clone()).is_err() {
            (st.next_ord, st.count, st.last_ms) = before;
            return AckStatus::Failed;
        }
        st.vectors.entry(*peer).or_default().mark(t.counter);
        st.confirm(peer);
        if self.save(st).is_err() {
            return AckStatus::Failed;
        }
        let mut shown = m;
        shown.ord = st.next_ord - 1;
        Self::push_event(g, t.gid, GroupEventKind::Received, Some(shown));
        AckStatus::Stored
    }

    fn handle_descs(
        &self,
        g: &mut Inner,
        peer: &[u8; 32],
        mut ds: Vec<Descriptor>,
        now: u64,
        trusted: &dyn Fn(&[u8; 32]) -> bool,
        kick: &mut Vec<[u8; 32]>,
    ) -> AckStatus {
        let gid = ds[0].gid;
        if ds.iter().any(|d| d.gid != gid) || !ds.windows(2).all(|w| w[0].epoch < w[1].epoch) {
            return AckStatus::BadRequest;
        }
        ds.shrink_to_fit();
        let auto_join = self.auto_join();
        let signer_is_peer = ds.last().is_some_and(|d| &d.signer == peer);
        if let Some(st) = g.groups.get_mut(&gid) {
            if !st.chain.ever_member(peer) && !signer_is_peer {
                return AckStatus::NotAllowed;
            }
            let was = st.status;
            match st.chain.push_all(ds) {
                Ok(false) => {
                    // Nothing new, but a device that sends descriptors has
                    // joined (a device that has not refuses to).
                    if st.chain.latest().is_member(peer) && st.confirm(peer) {
                        let _ = self.save(st);
                    }
                    return AckStatus::Duplicate;
                }
                Ok(true) => {}
                Err(DescError::Gap) => return AckStatus::BadRequest,
                Err(_) => return AckStatus::NotAllowed,
            }
            if st.chain.latest().is_member(peer) {
                st.confirm(peer);
            }
            let me_listed = st.chain.latest().is_member(&self.own);
            let mut joined_now = false;
            match (was, me_listed) {
                (Status::Joined, false) | (Status::Pending { .. }, false) => {
                    st.status = Status::Removed;
                }
                (Status::Left | Status::Removed, true) => {
                    // Added again by someone we trust: join at once, or ask
                    // first, as for a new invitation.
                    if trusted(peer) {
                        // What we knew of the members before is stale.
                        st.confirmed.clear();
                        if st.chain.latest().is_member(peer) {
                            st.confirm(peer);
                        }
                        if auto_join {
                            kick.extend(Self::become_member(st, self.own, *peer));
                            joined_now = true;
                        } else {
                            st.status = Status::Pending { invited_by: *peer };
                        }
                    }
                }
                _ => {}
            }
            Self::prune(st);
            if self.save(st).is_err() {
                return AckStatus::Failed;
            }
            let new_status = st.status;
            Self::push_event(
                g,
                gid,
                if joined_now {
                    GroupEventKind::Joined
                } else if matches!(new_status, Status::Pending { .. })
                    && !matches!(was, Status::Pending { .. })
                {
                    GroupEventKind::Invited
                } else {
                    GroupEventKind::Changed
                },
                None,
            );
            return AckStatus::Stored;
        }
        // A group we do not know: an invitation. Only a trusted contact who
        // is an admin and signed the newest descriptor may invite us.
        if !trusted(peer) || !signer_is_peer {
            return AckStatus::NotAllowed;
        }
        let latest = ds.last().expect("not empty");
        if !latest.is_member(&self.own) || !latest.is_admin(peer) {
            return AckStatus::NotAllowed;
        }
        let invites = g
            .groups
            .values()
            .filter(|s| matches!(s.status, Status::Pending { .. }))
            .count();
        if g.groups.len() >= MAX_GROUPS || invites >= MAX_INVITES {
            return AckStatus::Busy;
        }
        let mut chain = None;
        for i in 0..ds.len() {
            if let Ok(mut c) = Chain::from_root(ds[i].clone()) {
                if c.push_all(ds[i + 1..].to_vec()).is_ok() || i + 1 == ds.len() {
                    chain = Some(c);
                    break;
                }
            }
        }
        let Some(chain) = chain else {
            return AckStatus::NotAllowed;
        };
        if chain.epoch() != latest.epoch {
            return AckStatus::NotAllowed;
        }
        let mut st = GroupState::new(chain, Status::Pending { invited_by: *peer });
        st.last_ms = now;
        // The person who invited us has joined: they hold the group.
        st.confirm(peer);
        let kind = if auto_join {
            kick.extend(Self::become_member(&mut st, self.own, *peer));
            GroupEventKind::Joined
        } else {
            GroupEventKind::Invited
        };
        if self.save(&st).is_err() {
            return AckStatus::Failed;
        }
        g.groups.insert(gid, st);
        Self::push_event(g, gid, kind, None);
        AckStatus::Stored
    }

    // ── History ──────────────────────────────────────────────────────────────

    /// A page of the group's messages (the newest `limit`, or those before
    /// `before`), in display order.
    pub fn history(
        &self,
        gid: &[u8; 16],
        before: Option<u64>,
        limit: usize,
    ) -> Result<Vec<MessageView>, GroupError> {
        let limit = limit.clamp(1, crate::chat::store::MAX_PAGE);
        let (ledger, vectors): (HashMap<[u8; 16], LedgerEntry>, BTreeMap<[u8; 32], _>) = {
            let g = self.lock();
            let st = g.groups.get(gid).ok_or(GroupError::NotFound)?;
            (
                st.ledger.iter().map(|e| (e.id, *e)).collect(),
                st.vectors.clone(),
            )
        };
        let _ = vectors;
        let win = self.store.page(gid, before, limit);
        Ok(display_order(win)
            .into_iter()
            .map(|(m, gap)| MessageView {
                delivery: if m.outgoing {
                    ledger.get(&m.id).map(|l| (l.total, l.delivered, l.failed))
                } else {
                    None
                },
                msg: m,
                gap_before: gap,
            })
            .collect())
    }

    /// Delete the saved messages older than `cutoff_ms` (this device only).
    pub fn sweep_retention(&self, cutoff_ms: u64) -> usize {
        let gids: Vec<[u8; 16]> = self.lock().groups.keys().copied().collect();
        let mut removed = 0usize;
        for gid in gids {
            let mut total = 0u64;
            let kept = self.store.retain(&gid, |m| {
                total += 1;
                m.at_ms >= cutoff_ms
            });
            if let Ok(kept) = kept {
                removed += (total - kept.min(total)) as usize;
                let mut g = self.lock();
                if let Some(st) = g.groups.get_mut(&gid) {
                    st.count = kept;
                }
            }
        }
        removed
    }

    /// Write every state document (shutdown, tests that defer writes).
    pub fn flush_all(&self) {
        let g = self.lock();
        for st in g.groups.values() {
            if let Err(e) = self.store.write_state_now(st) {
                debug!("group state not written: {e}");
            }
        }
    }

    pub fn close(&self) {
        self.flush_all();
        self.store.close();
    }
}

/// Order a window of messages for display: by send time, but never reordering
/// one sender's messages against their counters. Also reports, per message,
/// how many counters of its sender below it are not in the window's run
/// (a visible gap) when the sender's previous counter is not adjacent.
fn display_order(win: Vec<GroupMsg>) -> Vec<(GroupMsg, u64)> {
    let mut by_sender: BTreeMap<[u8; 32], Vec<usize>> = BTreeMap::new();
    for (i, m) in win.iter().enumerate() {
        by_sender.entry(m.sender).or_default().push(i);
    }
    let mut key: Vec<(u64, [u8; 32], u64)> = vec![(0, [0; 32], 0); win.len()];
    let mut gap: Vec<u64> = vec![0; win.len()];
    for (sender, mut idx) in by_sender {
        idx.sort_by_key(|&i| win[i].counter);
        let mut running = 0u64;
        let mut prev: Option<u64> = None;
        for i in idx {
            running = running.max(win[i].sent_ms);
            key[i] = (running, sender, win[i].counter);
            if let Some(p) = prev {
                gap[i] = win[i].counter.saturating_sub(p + 1);
            }
            prev = Some(win[i].counter);
        }
    }
    let mut order: Vec<usize> = (0..win.len()).collect();
    order.sort_by_key(|&i| key[i]);
    order
        .into_iter()
        .map(|i| (win[i].clone(), gap[i]))
        .collect()
}

#[cfg(test)]
mod display_tests {
    use super::*;

    fn m(sender: u8, counter: u64, sent: u64) -> GroupMsg {
        GroupMsg {
            ord: counter + sender as u64 * 100,
            outgoing: false,
            sender: [sender; 32],
            counter,
            id: [counter as u8; 16],
            sent_ms: sent,
            at_ms: sent,
            epoch: 1,
            text: String::new(),
        }
    }

    #[test]
    fn a_senders_counters_keep_their_order_even_with_a_skewed_clock() {
        // Sender 1's second message claims an earlier time than its first.
        let shown = display_order(vec![m(1, 2, 50), m(1, 1, 100), m(2, 1, 70)]);
        let order: Vec<(u8, u64)> = shown
            .iter()
            .map(|(x, _)| (x.sender[0], x.counter))
            .collect();
        let p1 = order.iter().position(|x| *x == (1, 1)).unwrap();
        let p2 = order.iter().position(|x| *x == (1, 2)).unwrap();
        assert!(p1 < p2);
    }

    #[test]
    fn a_missing_counter_is_reported_as_a_gap() {
        let shown = display_order(vec![m(1, 1, 10), m(1, 4, 20)]);
        assert_eq!(shown[0].1, 0);
        assert_eq!(shown[1].1, 2);
    }
}
