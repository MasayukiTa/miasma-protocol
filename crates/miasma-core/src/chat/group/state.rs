//! What a device remembers about one group, and its encoding on disk.
//!
//! One encrypted document per group (`ChatGroups`):
//!
//! * the newest descriptors (the membership chain) and our standing in the group;
//! * our own message counter and, per sender, which counters were applied
//!   (the vector that makes delivery idempotent and shows gaps);
//! * the messages we sent that some member has not acknowledged yet, with the
//!   members still owed a copy;
//! * a short ledger of how our recent messages fared (for "delivered to k of n");
//! * control items owed to members (descriptors to push, sync requests).
//!
//! The messages themselves are in the group's record log ([`super::store`]).

use std::collections::{BTreeMap, VecDeque};

use crate::chat::{crypto::Rd, proto::MAX_TEXT_BYTES};

use super::membership::{Chain, Descriptor, MAX_CHAIN, MAX_MEMBERS};

/// Version 2 appends who added us and who has shown they joined; version 1
/// documents are still read (both fields empty).
const STATE_VERSION: u8 = 2;
const STATE_VERSION_V1: u8 = 1;
/// Messages of one group that may wait for delivery at once.
pub const MAX_PENDING: usize = 100;
/// Entries of the delivery ledger.
pub const MAX_LEDGER: usize = 200;
/// Control items owed at once.
pub const MAX_CTRL: usize = 256;
/// Applied counters kept above the floor, per sender.
pub const MAX_ABOVE: usize = 256;
/// Senders with a vector (every member of the held descriptors, with slack).
pub const MAX_VECTORS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Invited by this person (a trusted contact); not joined yet.
    Pending {
        invited_by: [u8; 32],
    },
    Joined,
    /// We left.
    Left,
    /// A valid descriptor no longer lists us.
    Removed,
}

impl Status {
    pub fn name(self) -> &'static str {
        match self {
            Status::Pending { .. } => "invited",
            Status::Joined => "joined",
            Status::Left => "left",
            Status::Removed => "removed",
        }
    }
}

/// Which counters of one sender were applied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SenderVec {
    /// Every counter up to here was applied (or given up on).
    pub floor: u64,
    /// Applied counters above the floor (sorted, bounded).
    pub above: Vec<u64>,
}

impl SenderVec {
    pub fn is_new(&self, c: u64) -> bool {
        c > self.floor && self.above.binary_search(&c).is_err()
    }

    /// Record `c`. A gap that stays open while more than [`MAX_ABOVE`] later
    /// counters arrive is given up on, so the set stays bounded.
    pub fn mark(&mut self, c: u64) {
        if c <= self.floor {
            return;
        }
        if let Err(i) = self.above.binary_search(&c) {
            self.above.insert(i, c);
        }
        while self.above.len() > MAX_ABOVE {
            self.floor = self.above.remove(0);
        }
        while let Some(&first) = self.above.first() {
            if first == self.floor + 1 {
                self.floor = first;
                self.above.remove(0);
            } else {
                break;
            }
        }
    }

    /// Counters between the floor and the highest applied one that have not
    /// arrived (yet).
    pub fn missing(&self) -> u64 {
        match self.above.last() {
            Some(&hi) => hi - self.floor - self.above.len() as u64,
            None => 0,
        }
    }

    pub fn highest(&self) -> u64 {
        self.above.last().copied().unwrap_or(self.floor)
    }
}

/// One message of ours that is still owed to some members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMsg {
    pub id: [u8; 16],
    pub counter: u64,
    pub epoch: u32,
    pub sent_ms: u64,
    pub text: String,
    pub to: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerEntry {
    pub id: [u8; 16],
    pub total: u8,
    pub delivered: u8,
    pub failed: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtrlKind {
    /// Push our newest descriptors.
    Descs,
    /// Ask for the descriptors that follow epoch `arg`.
    Sync,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ctrl {
    pub to: [u8; 32],
    pub kind: CtrlKind,
    pub arg: u32,
}

#[derive(Debug, Clone)]
pub struct GroupState {
    pub chain: Chain,
    pub status: Status,
    /// Last counter given to a message of ours.
    pub my_counter: u64,
    /// Next `ord` of the saved log (0 = not known yet).
    pub next_ord: u64,
    pub count: u64,
    pub last_ms: u64,
    pub vectors: BTreeMap<[u8; 32], SenderVec>,
    pub pending: Vec<PendingMsg>,
    pub ledger: VecDeque<LedgerEntry>,
    pub ctrl: Vec<Ctrl>,
    /// Who added us (a trusted administrator), once we joined through an invitation.
    pub added_by: Option<[u8; 32]>,
    /// Members that have shown they are in the group: something they sent us
    /// was accepted, or something we sent them was accepted by a joined device.
    pub confirmed: Vec<[u8; 32]>,
}

impl GroupState {
    /// Note that `peer` is in the group. True when this was news.
    pub fn confirm(&mut self, peer: &[u8; 32]) -> bool {
        if self.confirmed.contains(peer) || self.confirmed.len() >= MAX_MEMBERS {
            return false;
        }
        self.confirmed.push(*peer);
        true
    }

    pub fn new(chain: Chain, status: Status) -> Self {
        Self {
            chain,
            status,
            my_counter: 0,
            next_ord: 0,
            count: 0,
            last_ms: 0,
            vectors: BTreeMap::new(),
            pending: Vec::new(),
            ledger: VecDeque::new(),
            ctrl: Vec::new(),
            added_by: None,
            confirmed: Vec::new(),
        }
    }

    pub fn gid(&self) -> [u8; 16] {
        self.chain.gid()
    }

    pub fn name(&self) -> &str {
        &self.chain.latest().name
    }

    pub fn push_ledger(&mut self, e: LedgerEntry) {
        if self.ledger.len() >= MAX_LEDGER {
            self.ledger.pop_front();
        }
        self.ledger.push_back(e);
    }

    pub fn ledger_mut(&mut self, id: &[u8; 16]) -> Option<&mut LedgerEntry> {
        self.ledger.iter_mut().rev().find(|e| &e.id == id)
    }

    /// Owe `to` an item of `kind` unless one is already owed.
    pub fn owe(&mut self, to: [u8; 32], kind: CtrlKind, arg: u32) -> bool {
        if let Some(c) = self.ctrl.iter_mut().find(|c| c.to == to && c.kind == kind) {
            if kind == CtrlKind::Sync {
                c.arg = arg;
            }
            return false;
        }
        if self.ctrl.len() >= MAX_CTRL {
            return false;
        }
        self.ctrl.push(Ctrl { to, kind, arg });
        true
    }

    pub fn encode(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut w = zeroize::Zeroizing::new(Vec::with_capacity(4096));
        w.push(STATE_VERSION);
        match self.status {
            Status::Pending { invited_by } => {
                w.push(0);
                w.extend_from_slice(&invited_by);
            }
            Status::Joined => w.push(1),
            Status::Left => w.push(2),
            Status::Removed => w.push(3),
        }
        w.extend_from_slice(&self.my_counter.to_be_bytes());
        w.extend_from_slice(&self.next_ord.to_be_bytes());
        w.extend_from_slice(&self.count.to_be_bytes());
        w.extend_from_slice(&self.last_ms.to_be_bytes());
        let items = self.chain.items();
        w.push(items.len() as u8);
        for d in items {
            let e = d.encode();
            w.extend_from_slice(&(e.len() as u16).to_be_bytes());
            w.extend_from_slice(&e);
        }
        w.extend_from_slice(&(self.vectors.len() as u16).to_be_bytes());
        for (id, v) in &self.vectors {
            w.extend_from_slice(id);
            w.extend_from_slice(&v.floor.to_be_bytes());
            w.extend_from_slice(&(v.above.len() as u16).to_be_bytes());
            for a in &v.above {
                w.extend_from_slice(&a.to_be_bytes());
            }
        }
        w.extend_from_slice(&(self.pending.len() as u16).to_be_bytes());
        for p in &self.pending {
            w.extend_from_slice(&p.id);
            w.extend_from_slice(&p.counter.to_be_bytes());
            w.extend_from_slice(&p.epoch.to_be_bytes());
            w.extend_from_slice(&p.sent_ms.to_be_bytes());
            w.extend_from_slice(&(p.text.len() as u16).to_be_bytes());
            w.extend_from_slice(p.text.as_bytes());
            w.push(p.to.len() as u8);
            for t in &p.to {
                w.extend_from_slice(t);
            }
        }
        w.extend_from_slice(&(self.ledger.len() as u16).to_be_bytes());
        for e in &self.ledger {
            w.extend_from_slice(&e.id);
            w.push(e.total);
            w.push(e.delivered);
            w.push(e.failed);
        }
        w.extend_from_slice(&(self.ctrl.len() as u16).to_be_bytes());
        for c in &self.ctrl {
            w.extend_from_slice(&c.to);
            w.push(match c.kind {
                CtrlKind::Descs => 1,
                CtrlKind::Sync => 2,
            });
            w.extend_from_slice(&c.arg.to_be_bytes());
        }
        match self.added_by {
            Some(a) => {
                w.push(1);
                w.extend_from_slice(&a);
            }
            None => w.push(0),
        }
        w.push(self.confirmed.len() as u8);
        for c in &self.confirmed {
            w.extend_from_slice(c);
        }
        w
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Rd::new(b);
        let version = r.u8().ok()?;
        if version != STATE_VERSION && version != STATE_VERSION_V1 {
            return None;
        }
        let status = match r.u8().ok()? {
            0 => Status::Pending {
                invited_by: r.arr::<32>().ok()?,
            },
            1 => Status::Joined,
            2 => Status::Left,
            3 => Status::Removed,
            _ => return None,
        };
        let my_counter = r.u64().ok()?;
        let next_ord = r.u64().ok()?;
        let count = r.u64().ok()?;
        let last_ms = r.u64().ok()?;
        let nd = r.u8().ok()? as usize;
        if nd == 0 || nd > MAX_CHAIN {
            return None;
        }
        let mut items = Vec::with_capacity(nd);
        for _ in 0..nd {
            let n = r.u16().ok()? as usize;
            items.push(Descriptor::decode(r.bytes(n).ok()?).ok()?);
        }
        let chain = Chain::from_items(items).ok()?;
        let nv = r.u16().ok()? as usize;
        if nv > MAX_VECTORS {
            return None;
        }
        let mut vectors = BTreeMap::new();
        for _ in 0..nv {
            let id = r.arr::<32>().ok()?;
            let floor = r.u64().ok()?;
            let na = r.u16().ok()? as usize;
            if na > MAX_ABOVE {
                return None;
            }
            let mut above = Vec::with_capacity(na);
            for _ in 0..na {
                above.push(r.u64().ok()?);
            }
            if !above.windows(2).all(|w| w[0] < w[1]) || above.first().is_some_and(|f| *f <= floor)
            {
                return None;
            }
            vectors.insert(id, SenderVec { floor, above });
        }
        let np = r.u16().ok()? as usize;
        if np > MAX_PENDING {
            return None;
        }
        let mut pending = Vec::with_capacity(np);
        for _ in 0..np {
            let id = r.arr::<16>().ok()?;
            let counter = r.u64().ok()?;
            let epoch = r.u32().ok()?;
            let sent_ms = r.u64().ok()?;
            let n = r.u16().ok()? as usize;
            if n == 0 || n > MAX_TEXT_BYTES {
                return None;
            }
            let text = std::str::from_utf8(r.bytes(n).ok()?).ok()?.to_owned();
            let nt = r.u8().ok()? as usize;
            if nt > MAX_MEMBERS {
                return None;
            }
            let mut to = Vec::with_capacity(nt);
            for _ in 0..nt {
                to.push(r.arr::<32>().ok()?);
            }
            pending.push(PendingMsg {
                id,
                counter,
                epoch,
                sent_ms,
                text,
                to,
            });
        }
        let nl = r.u16().ok()? as usize;
        if nl > MAX_LEDGER {
            return None;
        }
        let mut ledger = VecDeque::with_capacity(nl);
        for _ in 0..nl {
            ledger.push_back(LedgerEntry {
                id: r.arr::<16>().ok()?,
                total: r.u8().ok()?,
                delivered: r.u8().ok()?,
                failed: r.u8().ok()?,
            });
        }
        let nc = r.u16().ok()? as usize;
        if nc > MAX_CTRL {
            return None;
        }
        let mut ctrl = Vec::with_capacity(nc);
        for _ in 0..nc {
            let to = r.arr::<32>().ok()?;
            let kind = match r.u8().ok()? {
                1 => CtrlKind::Descs,
                2 => CtrlKind::Sync,
                _ => return None,
            };
            ctrl.push(Ctrl {
                to,
                kind,
                arg: r.u32().ok()?,
            });
        }
        let mut added_by = None;
        let mut confirmed = Vec::new();
        if version >= 2 {
            added_by = match r.u8().ok()? {
                0 => None,
                1 => Some(r.arr::<32>().ok()?),
                _ => return None,
            };
            let n = r.u8().ok()? as usize;
            if n > MAX_MEMBERS {
                return None;
            }
            for _ in 0..n {
                confirmed.push(r.arr::<32>().ok()?);
            }
        }
        if !r.done() {
            return None;
        }
        Some(Self {
            chain,
            status,
            my_counter,
            next_ord,
            count,
            last_ms,
            vectors,
            pending,
            ledger,
            ctrl,
            added_by,
            confirmed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::group::membership::{Member, Role};
    use ed25519_dalek::SigningKey;

    fn chain() -> Chain {
        let k = SigningKey::from_bytes(&rand::random());
        let other = SigningKey::from_bytes(&rand::random());
        Chain::from_root(
            Descriptor {
                gid: rand::random(),
                epoch: 1,
                name: "grp".into(),
                created_ms: 5,
                prev_hash: [0; 32],
                members: vec![
                    Member {
                        id: k.verifying_key().to_bytes(),
                        role: Role::Admin,
                        hint: String::new(),
                    },
                    Member {
                        id: other.verifying_key().to_bytes(),
                        role: Role::Member,
                        hint: "bob".into(),
                    },
                ],
                signer: [0; 32],
                sig: [0; 64],
            }
            .signed(&k),
        )
        .unwrap()
    }

    #[test]
    fn vectors_apply_once_show_gaps_and_stay_bounded() {
        let mut v = SenderVec::default();
        assert!(v.is_new(1));
        v.mark(1);
        assert!(!v.is_new(1));
        v.mark(3);
        v.mark(4);
        assert_eq!((v.floor, v.above.clone()), (1, vec![3, 4]));
        assert_eq!(v.missing(), 1);
        assert_eq!(v.highest(), 4);
        assert!(!v.is_new(3));
        v.mark(2);
        assert_eq!((v.floor, v.above.len(), v.missing()), (4, 0, 0));
        // A gap that never fills is given up on.
        let mut w = SenderVec::default();
        for c in 2..(MAX_ABOVE as u64 + 10) {
            w.mark(c);
        }
        assert!(w.above.len() <= MAX_ABOVE);
        assert!(w.floor >= 9);
    }

    #[test]
    fn state_round_trips_and_damage_is_refused() {
        let mut s = GroupState::new(chain(), Status::Joined);
        s.my_counter = 7;
        s.next_ord = 12;
        s.count = 11;
        s.last_ms = 99;
        let sender = [3u8; 32];
        let mut v = SenderVec::default();
        v.mark(1);
        v.mark(5);
        s.vectors.insert(sender, v);
        s.pending.push(PendingMsg {
            id: [1; 16],
            counter: 7,
            epoch: 1,
            sent_ms: 9,
            text: "こんにちは".into(),
            to: vec![[4; 32], [5; 32]],
        });
        s.push_ledger(LedgerEntry {
            id: [1; 16],
            total: 2,
            delivered: 0,
            failed: 0,
        });
        s.owe([4; 32], CtrlKind::Descs, 0);
        s.owe([5; 32], CtrlKind::Sync, 3);
        s.added_by = Some([6; 32]);
        assert!(s.confirm(&[4; 32]));
        assert!(!s.confirm(&[4; 32]));
        let bytes = s.encode();
        let back = GroupState::decode(&bytes).unwrap();
        assert_eq!(back.added_by, Some([6; 32]));
        assert_eq!(back.confirmed, vec![[4; 32]]);
        assert_eq!(back.chain, s.chain);
        assert_eq!(back.status, Status::Joined);
        assert_eq!(
            (back.my_counter, back.next_ord, back.count, back.last_ms),
            (7, 12, 11, 99)
        );
        assert_eq!(back.vectors, s.vectors);
        assert_eq!(back.pending, s.pending);
        assert_eq!(back.ledger, s.ledger);
        assert_eq!(back.ctrl, s.ctrl);
        for n in 0..bytes.len() {
            assert!(GroupState::decode(&bytes[..n]).is_none(), "prefix {n}");
        }
        let pending = GroupState::new(
            chain(),
            Status::Pending {
                invited_by: [8; 32],
            },
        );
        let again = GroupState::decode(&pending.encode()).unwrap();
        assert_eq!(
            again.status,
            Status::Pending {
                invited_by: [8; 32]
            }
        );
    }

    #[test]
    fn a_document_from_before_these_fields_still_reads() {
        let s = GroupState::new(chain(), Status::Joined);
        let mut bytes = s.encode().to_vec();
        // Version 2 ends with "no added_by" (1 byte) and "no confirmed" (1 byte).
        bytes.truncate(bytes.len() - 2);
        bytes[0] = STATE_VERSION_V1;
        let back = GroupState::decode(&bytes).expect("a version 1 document");
        assert_eq!(back.added_by, None);
        assert!(back.confirmed.is_empty());
        assert_eq!(back.status, Status::Joined);
    }

    #[test]
    fn owing_the_same_thing_twice_keeps_one_item() {
        let mut s = GroupState::new(chain(), Status::Joined);
        assert!(s.owe([1; 32], CtrlKind::Descs, 0));
        assert!(!s.owe([1; 32], CtrlKind::Descs, 0));
        assert!(s.owe([1; 32], CtrlKind::Sync, 2));
        assert!(!s.owe([1; 32], CtrlKind::Sync, 4));
        assert_eq!(s.ctrl.len(), 2);
        assert_eq!(s.ctrl[1].arg, 4);
    }

    #[test]
    fn random_bytes_never_panic_the_decoder() {
        for _ in 0..2000 {
            let n = rand::random::<usize>() % 300;
            let mut junk: Vec<u8> = (0..n).map(|_| rand::random()).collect();
            if let Some(f) = junk.first_mut() {
                *f = STATE_VERSION;
            }
            let _ = GroupState::decode(&junk);
        }
    }
}
