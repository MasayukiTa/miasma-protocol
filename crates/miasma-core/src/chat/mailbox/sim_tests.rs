//! Three nodes in one process: a sender, a recipient who is offline, and a
//! third trusted contact that holds the sealed envelope in between. The
//! "network" is a table of in-memory stores; a node that is offline cannot be
//! reached.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use super::{
    client::{MailboxClient, MailboxError, MailboxTransport},
    holder::{
        CustodyError, CustodyLimits, CustodyStore, DepositOutcome, MemoryCustody, MAX_ITEM_BYTES,
    },
    ids::{item_id_of, ItemId, RecipientTag},
};
use crate::chat::{
    offline_tests::{catch_up, side, Side},
    proto::AckStatus,
};

const DAY: u64 = 86_400_000;

/// Who is up, and what each node holds.
#[derive(Default)]
struct Net {
    holders: Mutex<HashMap<[u8; 32], Arc<MemoryCustody>>>,
    offline: Mutex<HashSet<[u8; 32]>>,
}

impl Net {
    fn add_holder(&self, id: [u8; 32], limits: CustodyLimits, trusts: &[[u8; 32]]) {
        let h = MemoryCustody::new(limits);
        for t in trusts {
            h.trust(*t);
        }
        self.holders.lock().unwrap().insert(id, Arc::new(h));
    }

    fn holder(&self, id: &[u8; 32]) -> Arc<MemoryCustody> {
        self.holders.lock().unwrap().get(id).unwrap().clone()
    }

    fn set_offline(&self, id: [u8; 32], off: bool) {
        let mut o = self.offline.lock().unwrap();
        if off {
            o.insert(id);
        } else {
            o.remove(&id);
        }
    }

    fn reach(&self, id: &[u8; 32]) -> Result<Arc<MemoryCustody>, MailboxError> {
        if self.offline.lock().unwrap().contains(id) {
            return Err(MailboxError::Unreachable);
        }
        self.holders
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(MailboxError::Unreachable)
    }
}

/// The transport of one node: the caller's ID is what the holder sees.
struct SimTransport {
    me: [u8; 32],
    net: Arc<Net>,
}

impl MailboxTransport for SimTransport {
    fn deposit(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        blob: &[u8],
        now_ms: u64,
    ) -> Result<DepositOutcome, MailboxError> {
        self.net
            .reach(holder)?
            .deposit(&self.me, tag, item, blob, now_ms)
            .map_err(MailboxError::Refused)
    }

    fn list(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        now_ms: u64,
    ) -> Result<Vec<ItemId>, MailboxError> {
        self.net
            .reach(holder)?
            .list(&self.me, tag, now_ms)
            .map_err(MailboxError::Refused)
    }

    fn fetch(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, MailboxError> {
        self.net
            .reach(holder)?
            .fetch(&self.me, tag, item, now_ms)
            .map_err(MailboxError::Refused)
    }

    fn delete(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
    ) -> Result<bool, MailboxError> {
        self.net
            .reach(holder)?
            .delete(&self.me, tag, item)
            .map_err(MailboxError::Refused)
    }
}

fn on() -> CustodyLimits {
    CustodyLimits {
        enabled: true,
        ..CustodyLimits::default()
    }
}

fn client(net: &Arc<Net>, me: [u8; 32], copies: usize) -> MailboxClient<SimTransport> {
    MailboxClient::new(
        SimTransport {
            me,
            net: net.clone(),
        },
        copies,
    )
}

/// Seal the oldest message of `from` for `to` and put a copy with `holders`.
fn deposit_oldest(
    c: &MailboxClient<SimTransport>,
    from: &Side,
    to: &Side,
    holders: &[[u8; 32]],
    now: u64,
) -> (ItemId, usize) {
    let e = from.core.outbox.first_for(&to.id()).unwrap();
    let (wire, _) = from.core.prepare_wire(&e.id).unwrap();
    let item = item_id_of(&wire).unwrap();
    let rep = c.deposit(holders, &from.id(), &to.id(), item, &wire, now);
    (item, rep.held_by.len())
}

/// The recipient applies what it collects exactly as a direct delivery.
fn collect_into(
    c: &MailboxClient<SimTransport>,
    me: &Side,
    holders: &[[u8; 32]],
    now: u64,
) -> (super::client::CollectReport, Vec<AckStatus>) {
    let mut statuses = Vec::new();
    let rep = c.collect(holders, &me.id(), now, |sender, wire| {
        let st = me.core.accept(sender, wire, now).status;
        statuses.push(st);
        st.is_delivered()
    });
    (rep, statuses)
}

#[test]
fn a_message_reaches_an_offline_recipient_through_a_third_trusted_node() {
    let (a, b, c) = (side(), side(), side());
    let net = Arc::new(Net::default());
    // C holds for its contacts A and B; B is offline.
    net.add_holder(c.id(), on(), &[a.id(), b.id()]);
    net.set_offline(b.id(), true);
    for t in ["while you were away", "and a second"] {
        a.core.enqueue(&b.id(), t, 1).unwrap();
    }
    let ca = client(&net, a.id(), 1);
    let (item, n) = deposit_oldest(&ca, &a, &b, &[c.id()], 1_000);
    assert_eq!(n, 1);
    assert_eq!(net.holder(&c.id()).stats().items, 1);
    // The holder keeps the sealed bytes: the text is not in them.
    let held = net
        .holder(&c.id())
        .fetch(&a.id(), RecipientTag::for_recipient(&b.id()), item, 1_000)
        .unwrap()
        .unwrap();
    assert!(!held.windows(5).any(|w| w == b"while"));

    // B comes back and asks C.
    net.set_offline(b.id(), false);
    let cb = client(&net, b.id(), 1);
    let (rep, st) = collect_into(&cb, &b, &[c.id()], 2_000);
    assert_eq!((rep.offered, rep.taken), (1, 1));
    assert_eq!(st, [AckStatus::Stored]);
    assert_eq!(b.received(&a.id()), ["while you were away"]);
    // The holder let go of it.
    assert_eq!(net.holder(&c.id()).stats().items, 0);

    // A reaches B later: the catch-up closes the first message without
    // sending it, and only the second goes over.
    assert_eq!(catch_up(&a, &b), 1);
    assert_eq!(a.core.outbox.len(), 1);
    let e = a.core.outbox.first_for(&b.id()).unwrap();
    let (wire, _) = a.core.prepare_wire(&e.id).unwrap();
    assert_eq!(b.core.accept(&a.id(), &wire, 3_000).status, AckStatus::Stored);
    a.core.mark_delivered(&e.id, 3_001);
    assert_eq!(
        b.received(&a.id()),
        ["while you were away", "and a second"]
    );
    assert_eq!(a.delivered(&b.id()), ["while you were away", "and a second"]);
}

#[test]
fn the_copy_in_custody_and_the_direct_send_do_not_double_up() {
    let (a, b, c) = (side(), side(), side());
    let net = Arc::new(Net::default());
    net.add_holder(c.id(), on(), &[a.id(), b.id()]);
    a.core.enqueue(&b.id(), "once only", 1).unwrap();
    let ca = client(&net, a.id(), 1);
    deposit_oldest(&ca, &a, &b, &[c.id()], 10);
    // The direct delivery happens first ...
    let e = a.core.outbox.first_for(&b.id()).unwrap();
    let (wire, _) = a.core.prepare_wire(&e.id).unwrap();
    assert_eq!(b.core.accept(&a.id(), &wire, 11).status, AckStatus::Stored);
    a.core.mark_delivered(&e.id, 12);
    // ... then B also collects the copy: a duplicate, dropped, and removed.
    let cb = client(&net, b.id(), 1);
    let (rep, st) = collect_into(&cb, &b, &[c.id()], 13);
    assert_eq!(st, [AckStatus::Duplicate]);
    assert_eq!(rep.taken, 1);
    assert_eq!(b.received(&a.id()), ["once only"]);
    assert_eq!(net.holder(&c.id()).stats().items, 0);
    // Collecting again finds nothing.
    let (rep, st) = collect_into(&cb, &b, &[c.id()], 14);
    assert_eq!((rep.offered, st.len()), (0, 0));
}

#[test]
fn copies_at_two_holders_are_applied_once() {
    let (a, b, c, d) = (side(), side(), side(), side());
    let net = Arc::new(Net::default());
    for h in [&c, &d] {
        net.add_holder(h.id(), on(), &[a.id(), b.id()]);
    }
    a.core.enqueue(&b.id(), "twice held", 1).unwrap();
    let ca = client(&net, a.id(), 2);
    let (_, n) = deposit_oldest(&ca, &a, &b, &[c.id(), d.id()], 10);
    assert_eq!(n, 2);
    let cb = client(&net, b.id(), 2);
    let (rep, st) = collect_into(&cb, &b, &[c.id(), d.id()], 20);
    assert_eq!((rep.offered, rep.repeated, rep.taken), (1, 1, 1));
    assert_eq!(st, [AckStatus::Stored]);
    assert_eq!(b.received(&a.id()), ["twice held"]);
    // Both copies are gone, not only the one that was read.
    assert_eq!(net.holder(&c.id()).stats().items, 0);
    assert_eq!(net.holder(&d.id()).stats().items, 0);
}

#[test]
fn a_holder_that_is_down_or_off_is_skipped() {
    let (a, b, c, d, e) = (side(), side(), side(), side(), side());
    let net = Arc::new(Net::default());
    net.add_holder(c.id(), on(), &[a.id(), b.id()]);
    // D is up but holding is off (the default); E is down.
    net.add_holder(d.id(), CustodyLimits::default(), &[a.id(), b.id()]);
    net.add_holder(e.id(), on(), &[a.id(), b.id()]);
    net.set_offline(e.id(), true);
    a.core.enqueue(&b.id(), "x", 1).unwrap();
    let ca = client(&net, a.id(), 1);
    let en = a.core.outbox.first_for(&b.id()).unwrap();
    let (wire, _) = a.core.prepare_wire(&en.id).unwrap();
    let rep = ca.deposit(
        &[e.id(), d.id(), c.id()],
        &a.id(),
        &b.id(),
        item_id_of(&wire).unwrap(),
        &wire,
        5,
    );
    assert_eq!(rep.held_by, vec![c.id()]);
    assert_eq!(rep.failed.len(), 2);
    assert!(rep
        .failed
        .iter()
        .any(|(h, er)| *h == d.id() && *er == MailboxError::Refused(CustodyError::Disabled)));
    assert!(rep
        .failed
        .iter()
        .any(|(h, er)| *h == e.id() && *er == MailboxError::Unreachable));
    // A contact the holder does not trust cannot use it.
    let stranger = side();
    let cs = client(&net, stranger.id(), 1);
    let rep = cs.deposit(&[c.id()], &stranger.id(), &b.id(), ItemId([5; 16]), b"abc", 5);
    assert!(rep.held_by.is_empty());
    assert_eq!(
        rep.failed[0].1,
        MailboxError::Refused(CustodyError::NotTrusted)
    );
}

#[test]
fn an_item_expires_and_the_message_is_then_delivered_directly() {
    let (a, b, c) = (side(), side(), side());
    let net = Arc::new(Net::default());
    net.add_holder(c.id(), CustodyLimits { ttl_ms: DAY, ..on() }, &[a.id(), b.id()]);
    a.core.enqueue(&b.id(), "late", 1).unwrap();
    let ca = client(&net, a.id(), 1);
    deposit_oldest(&ca, &a, &b, &[c.id()], 0);
    let cb = client(&net, b.id(), 1);
    // B asks after the item has expired: nothing is offered.
    let (rep, st) = collect_into(&cb, &b, &[c.id()], DAY);
    assert_eq!((rep.offered, st.len()), (0, 0));
    assert_eq!(net.holder(&c.id()).stats().items, 0);
    assert!(b.received(&a.id()).is_empty());
    // The sender still has it, with the same envelope, and delivers it.
    assert_eq!(a.core.outbox.len(), 1);
    let e = a.core.outbox.first_for(&b.id()).unwrap();
    let (wire, _) = a.core.prepare_wire(&e.id).unwrap();
    assert_eq!(b.core.accept(&a.id(), &wire, DAY + 1).status, AckStatus::Stored);
    assert_eq!(b.received(&a.id()), ["late"]);
}

#[test]
fn the_holder_limits_hold_under_a_flood() {
    let (a, b, c) = (side(), side(), side());
    let net = Arc::new(Net::default());
    let limits = CustodyLimits {
        max_items: 20,
        max_items_per_depositor: 8,
        max_bytes_per_depositor: 16 * 1024,
        max_total_bytes: 32 * 1024,
        ..on()
    };
    net.add_holder(c.id(), limits, &[a.id(), b.id()]);
    let ca = client(&net, a.id(), 1);
    let mut stored = 0;
    let mut budget = 0;
    for n in 0..50u8 {
        let rep = ca.deposit(&[c.id()], &a.id(), &b.id(), ItemId([n; 16]), &[7u8; 1000], 1);
        match rep.failed.first() {
            None => stored += 1,
            Some((_, MailboxError::Refused(CustodyError::DepositorBudget))) => budget += 1,
            Some(other) => panic!("{other:?}"),
        }
    }
    assert_eq!(stored, 8);
    assert_eq!(budget, 42);
    // Another contact is not shut out by A's flood, up to the total.
    let cb = client(&net, b.id(), 1);
    let mut b_stored = 0;
    for n in 100..130u8 {
        if cb
            .deposit(&[c.id()], &b.id(), &a.id(), ItemId([n; 16]), &[7u8; 1000], 1)
            .failed
            .is_empty()
        {
            b_stored += 1;
        }
    }
    assert_eq!(b_stored, 8);
    let st = net.holder(&c.id()).stats();
    assert_eq!(st.items, 16);
    assert!(st.bytes <= 32 * 1024);
    // An oversize item is refused outright.
    let rep = ca.deposit(
        &[c.id()],
        &a.id(),
        &b.id(),
        ItemId([200; 16]),
        &vec![1u8; MAX_ITEM_BYTES],
        1,
    );
    assert_eq!(
        rep.failed[0].1,
        MailboxError::Refused(CustodyError::TooBig)
    );
}

#[test]
fn junk_in_custody_is_not_applied() {
    let (a, b, c) = (side(), side(), side());
    let net = Arc::new(Net::default());
    net.add_holder(c.id(), on(), &[a.id(), b.id()]);
    // A trusted contact puts garbage (and a too-short item) in B's tag.
    let ca = client(&net, a.id(), 1);
    ca.deposit(&[c.id()], &a.id(), &b.id(), ItemId([1; 16]), &[9u8; 300], 1);
    net.holder(&c.id())
        .deposit(
            &a.id(),
            RecipientTag::for_recipient(&b.id()),
            ItemId([2; 16]),
            &[1u8; 10],
            1,
        )
        .unwrap();
    let cb = client(&net, b.id(), 1);
    let (rep, st) = collect_into(&cb, &b, &[c.id()], 2);
    // The short item is skipped; the garbage envelope is offered, refused and
    // therefore left in place (it expires).
    assert_eq!((rep.offered, rep.taken), (1, 0));
    assert_eq!(st.len(), 1);
    assert!(!st[0].is_delivered(), "{:?}", st[0]);
    assert!(b.received(&a.id()).is_empty());
}
