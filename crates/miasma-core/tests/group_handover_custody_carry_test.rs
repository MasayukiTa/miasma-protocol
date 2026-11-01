//! Two behaviours the custody carriage of a group hand-over offer must have
//! (ADR-012 step 5), exercised through the public custody client with a tiny
//! in-memory transport: no network and no platform-specific code, so this file
//! is listed explicitly in the CI core-test set.
//!
//! 1. An offer deposited while the new member is offline is applied exactly
//!    once after the member reconnects -- including the case where the same
//!    message also reached the member directly, where the offer must be a
//!    no-op and must still be dropped by the holder.
//! 2. With custody off, nothing is deposited: the offer stays in the sender
//!    outbox and no holder is given anything.

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

use miasma_core::chat::mailbox::{
    client::{MailboxClient, MailboxError, MailboxTransport},
    holder::DepositOutcome,
    ids::{ItemId, RecipientTag},
};

/// An in-memory stand-in for the set of holders: one map keyed by
/// (holder, tag, item). Enough to show what a collector can and cannot see.
#[derive(Default)]
struct MemTransport {
    items: Mutex<HashMap<([u8; 32], [u8; 16], [u8; 16]), Vec<u8>>>,
}

impl MailboxTransport for MemTransport {
    fn deposit(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        blob: &[u8],
        _now_ms: u64,
    ) -> Result<DepositOutcome, MailboxError> {
        let mut m = self.items.lock().unwrap();
        let key = (*holder, tag.0, item.0);
        if m.contains_key(&key) {
            return Ok(DepositOutcome::Duplicate);
        }
        m.insert(key, blob.to_vec());
        Ok(DepositOutcome::Stored)
    }

    fn list(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        _now_ms: u64,
    ) -> Result<Vec<ItemId>, MailboxError> {
        let m = self.items.lock().unwrap();
        Ok(m.keys()
            .filter(|(h, t, _)| h == holder && *t == tag.0)
            .map(|(_, _, i)| ItemId(*i))
            .collect())
    }

    fn fetch(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
        _now_ms: u64,
    ) -> Result<Option<Vec<u8>>, MailboxError> {
        let m = self.items.lock().unwrap();
        Ok(m.get(&(*holder, tag.0, item.0)).cloned())
    }

    fn delete(
        &self,
        holder: &[u8; 32],
        tag: RecipientTag,
        item: ItemId,
    ) -> Result<bool, MailboxError> {
        let mut m = self.items.lock().unwrap();
        Ok(m.remove(&(*holder, tag.0, item.0)).is_some())
    }
}

const HOLDER: [u8; 32] = [10u8; 32];
const SENDER: [u8; 32] = [20u8; 32];
const MEMBER: [u8; 32] = [30u8; 32];

/// A sealed group-offer body carrying the sender id in front, the shape the
/// collector splits back out. `marker` stands in for the original message id so
/// the applying side can tell two offers of the same message apart from two
/// different messages.
fn offer_blob(marker: u8) -> Vec<u8> {
    let mut b = SENDER.to_vec();
    b.extend_from_slice(b"sealed group offer body");
    b.push(marker);
    b
}

/// The applying side, standing in for the group receive path: it keeps the set
/// of message markers it has already applied (whether from a direct delivery or
/// an earlier offer) and treats a repeat as an already-known no-op. Like the
/// real path it returns true for an already-known item too, so the holder drops
/// its copy either way.
struct GroupApply {
    applied: HashSet<u8>,
    fresh_applies: usize,
}

impl GroupApply {
    fn new() -> Self {
        Self {
            applied: HashSet::new(),
            fresh_applies: 0,
        }
    }

    fn apply(&mut self, _sender: &[u8; 32], wire: &[u8]) -> bool {
        let marker = *wire.last().expect("offer body is never empty");
        if self.applied.insert(marker) {
            self.fresh_applies += 1;
        }
        true
    }
}

/// A HistOffer deposited while the member is offline is collected and applied
/// exactly once after reconnect, and the holder drops it. A second collection
/// takes nothing because the holder no longer has it.
#[test]
fn an_offline_offer_is_applied_exactly_once_after_reconnect() {
    let client = MailboxClient::new(MemTransport::default(), 1);
    let item = ItemId([1u8; 16]);
    let wire = offer_blob(0xA1);

    let dep = client.deposit_group(&[HOLDER], &SENDER, &MEMBER, item, &wire, 0);
    assert_eq!(dep.held_by, vec![HOLDER], "the holder takes the offer");

    let mut apply = GroupApply::new();
    let first = client.collect_group(&[HOLDER], &MEMBER, 0, |s, w| apply.apply(s, w));
    assert_eq!(first.taken, 1, "the offer is collected once on reconnect");
    assert_eq!(apply.fresh_applies, 1, "and applied once");

    let second = client.collect_group(&[HOLDER], &MEMBER, 0, |s, w| apply.apply(s, w));
    assert_eq!(second.taken, 0, "the holder has nothing left to hand back");
    assert_eq!(apply.fresh_applies, 1, "still applied exactly once");
}

/// The same message also reached the member directly. The offer collected from
/// the holder is then an already-known no-op on apply, so the member applies it
/// exactly once in total, and the holder still drops the copy.
#[test]
fn an_offer_already_delivered_directly_is_a_noop_but_still_dropped() {
    let client = MailboxClient::new(MemTransport::default(), 1);
    let item = ItemId([2u8; 16]);
    let wire = offer_blob(0xB2);

    let dep = client.deposit_group(&[HOLDER], &SENDER, &MEMBER, item, &wire, 0);
    assert_eq!(dep.held_by, vec![HOLDER]);

    let mut apply = GroupApply::new();
    apply.apply(&SENDER, &wire);
    assert_eq!(apply.fresh_applies, 1, "the direct copy is applied once");

    let rep = client.collect_group(&[HOLDER], &MEMBER, 0, |s, w| apply.apply(s, w));
    assert_eq!(
        rep.taken, 1,
        "the offer is taken and removed from the holder"
    );
    assert_eq!(
        apply.fresh_applies, 1,
        "the already-delivered message is not applied a second time"
    );

    let again = client.collect_group(&[HOLDER], &MEMBER, 0, |s, w| apply.apply(s, w));
    assert_eq!(again.taken, 0);
    assert_eq!(apply.fresh_applies, 1);
}

/// Stands in for the sender side deciding whether to carry an offer through
/// custody, mirroring the service: with custody off it never deposits and the
/// offer is kept in the outbox; with custody on it deposits with a holder and
/// the offer leaves the outbox.
fn carry_offer(
    client: &MailboxClient<MemTransport>,
    custody_enabled: bool,
    outbox: &mut Vec<ItemId>,
    item: ItemId,
    wire: &[u8],
) -> bool {
    if !custody_enabled {
        return false;
    }
    let dep = client.deposit_group(&[HOLDER], &SENDER, &MEMBER, item, wire, 0);
    if dep.held_by.is_empty() {
        return false;
    }
    outbox.retain(|queued| queued.0 != item.0);
    true
}

/// With custody disabled nothing is deposited: no holder is given the offer and
/// it stays in the sender outbox, and a later group collection finds nothing.
#[test]
fn with_custody_disabled_nothing_is_deposited() {
    let client = MailboxClient::new(MemTransport::default(), 1);
    let item = ItemId([3u8; 16]);
    let wire = offer_blob(0xC3);

    let mut outbox = vec![item];
    let carried = carry_offer(&client, false, &mut outbox, item, &wire);
    assert!(!carried, "custody off carries nothing");
    assert_eq!(outbox, vec![item], "the offer stays in the sender outbox");

    let mut applied = 0usize;
    let rep = client.collect_group(&[HOLDER], &MEMBER, 0, |_s, _w| {
        applied += 1;
        true
    });
    assert_eq!(
        rep.taken, 0,
        "nothing was deposited, so nothing is collected"
    );
    assert_eq!(applied, 0, "the member applies no offer from custody");
}

/// The matching custody-on case, so the disabled test above is a real contrast
/// and not merely the empty state: with custody on the offer is deposited, it
/// leaves the outbox, and the member collects it once.
#[test]
fn with_custody_enabled_the_offer_is_deposited_and_leaves_the_outbox() {
    let client = MailboxClient::new(MemTransport::default(), 1);
    let item = ItemId([4u8; 16]);
    let wire = offer_blob(0xD4);

    let mut outbox = vec![item];
    let carried = carry_offer(&client, true, &mut outbox, item, &wire);
    assert!(carried, "custody on deposits the offer");
    assert!(outbox.is_empty(), "the deposited offer leaves the outbox");

    let mut apply = GroupApply::new();
    let rep = client.collect_group(&[HOLDER], &MEMBER, 0, |s, w| apply.apply(s, w));
    assert_eq!(rep.taken, 1, "the member collects the deposited offer once");
    assert_eq!(apply.fresh_applies, 1);
}
