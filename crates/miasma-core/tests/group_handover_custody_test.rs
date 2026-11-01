//! A group hand-over offer carried through the custody layer (ADR-012 step 5)
//! keeps to its own tag, so it is only ever collected and applied through the
//! group path, never as a private message, and the other way round. Exercised
//! through the public custody client with a tiny in-memory transport: no
//! network and no platform-specific code, so it is listed explicitly in the CI
//! core-test set alongside the wire-format test.

use std::{collections::HashMap, sync::Mutex};

use miasma_core::chat::mailbox::{
    client::{MailboxClient, MailboxError, MailboxTransport},
    holder::DepositOutcome,
    ids::{ItemId, RecipientTag},
};

/// An in-memory stand-in for a holder: one map keyed by (holder, tag, item).
/// It is enough to show that a tag separates what a collector can see.
#[derive(Default)]
struct MemTransport {
    // (holder, tag, item) -> blob
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
const RECIPIENT: [u8; 32] = [30u8; 32];

/// A non-empty sealed body. The client puts the sender id in front when it
/// deposits, and the collector splits it back out, so the body itself must not
/// carry one.
fn blob() -> Vec<u8> {
    b"sealed group offer body".to_vec()
}

/// A group offer deposited for an offline member is collected through the group
/// path, and is never seen on the private path for the same contact.
#[test]
fn a_group_offer_is_collected_as_a_group_item_not_a_private_one() {
    let client = MailboxClient::new(MemTransport::default(), 1);
    let item = ItemId([1u8; 16]);
    let wire = blob();

    let dep = client.deposit_group(&[HOLDER], &SENDER, &RECIPIENT, item, &wire, 0);
    assert_eq!(
        dep.held_by,
        vec![HOLDER],
        "the holder takes the group offer"
    );

    // The private path finds nothing for the same recipient: a group offer is
    // never applied as a private message.
    let mut private_bodies = Vec::new();
    let priv_rep = client.collect(&[HOLDER], &RECIPIENT, 0, |_s, body| {
        private_bodies.push(body.to_vec());
        true
    });
    assert_eq!(priv_rep.taken, 0, "the private path sees no group offer");
    assert!(private_bodies.is_empty());

    // The group path collects it once, with the sender and body intact.
    let mut got: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let grp_rep = client.collect_group(&[HOLDER], &RECIPIENT, 0, |s, body| {
        got.push((s.to_vec(), body.to_vec()));
        true
    });
    assert_eq!(grp_rep.taken, 1, "the group path collects the offer once");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, SENDER, "the sender id is carried through");
    assert_eq!(got[0].1, b"sealed group offer body");

    // It was removed on collection, so a second group round takes nothing.
    let again = client.collect_group(&[HOLDER], &RECIPIENT, 0, |_s, _b| true);
    assert_eq!(
        again.taken, 0,
        "a collected group offer is not offered twice"
    );
}

/// The mirror: a private deposit for a contact is invisible to the group path,
/// so the recipient never applies a private message as a group item.
#[test]
fn a_private_message_is_not_collected_as_a_group_offer() {
    let client = MailboxClient::new(MemTransport::default(), 1);
    let item = ItemId([2u8; 16]);
    let wire = blob();

    let dep = client.deposit(&[HOLDER], &SENDER, &RECIPIENT, item, &wire, 0);
    assert_eq!(dep.held_by, vec![HOLDER]);

    let grp_rep = client.collect_group(&[HOLDER], &RECIPIENT, 0, |_s, _b| true);
    assert_eq!(
        grp_rep.taken, 0,
        "the group path never picks up a private message"
    );

    // The private path still collects it, proving the deposit was there all
    // along and only the tag kept the group path from seeing it.
    let priv_rep = client.collect(&[HOLDER], &RECIPIENT, 0, |_s, _b| true);
    assert_eq!(priv_rep.taken, 1, "the private path collects its own item");
}

/// With custody off the group service never deposits an offer: nothing is left
/// with a holder and the offer waits in the sender outbox as before. Here that
/// end state is shown directly -- a holder that was never given an offer hands
/// back nothing when the member comes online and collects through the group
/// path, so the member applies nothing from custody.
#[test]
fn with_no_offer_deposited_the_group_collect_takes_nothing() {
    let client = MailboxClient::new(MemTransport::default(), 1);

    // No deposit_group call was made (the custody-off path makes none), so the
    // holder holds nothing for this member on the group tag.
    let mut applied = 0usize;
    let rep = client.collect_group(&[HOLDER], &RECIPIENT, 0, |_s, _b| {
        applied += 1;
        true
    });
    assert_eq!(
        rep.taken, 0,
        "nothing was deposited, so nothing is collected"
    );
    assert_eq!(
        applied, 0,
        "the member applies no hand-over offer from custody"
    );
}
