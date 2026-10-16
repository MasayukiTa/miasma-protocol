//! Tests of delivery across pauses, without a network: the sealed envelope
//! kept across restarts, and the catch-up between two engines.

use std::sync::Arc;

use tempfile::TempDir;

use super::{
    crypto::Identity,
    engine::ChatCore,
    outbox::Outbox,
    proto::{AckStatus, SyncItem, MAX_SYNC_ITEMS},
    store::{ChatStore, MsgState, StoreSettings},
    sync,
};
use crate::state_crypto::StateKeys;

pub(crate) struct Side {
    pub(crate) dir: TempDir,
    seed: [u8; 32],
    master: [u8; 32],
    pub(crate) core: ChatCore,
}

fn open_core(dir: &std::path::Path, seed: &[u8; 32], master: &[u8; 32], max: usize) -> ChatCore {
    let keys = Arc::new(StateKeys::from_master_key(master).unwrap());
    let id = Identity::from_seed(seed);
    let chat = dir.join("chat");
    let s = StoreSettings::default();
    let store = ChatStore::open(&chat, keys.clone(), id.id(), s.clone()).unwrap();
    let (outbox, _) = Outbox::open(&crate::paths::chat_outbox_file(&chat), keys, s, 1);
    ChatCore::new(store, outbox, id, max)
}

fn side_with_max(max: usize) -> Side {
    let dir = tempfile::tempdir().unwrap();
    let seed: [u8; 32] = rand::random();
    let master: [u8; 32] = rand::random();
    let core = open_core(dir.path(), &seed, &master, max);
    Side {
        dir,
        seed,
        master,
        core,
    }
}

pub(crate) fn side() -> Side {
    side_with_max(4096)
}

impl Side {
    pub(crate) fn id(&self) -> [u8; 32] {
        self.core.own_id()
    }

    fn restart(&mut self) {
        self.core.store.close();
        self.core = open_core(self.dir.path(), &self.seed, &self.master, 4096);
    }

    fn session_bytes(&self, peer: &[u8; 32]) -> Option<Vec<u8>> {
        self.core
            .store
            .peek_peer(peer, |st| st.session.as_ref().map(|s| s.to_bytes().to_vec()))
    }

    /// Texts received from `peer`, in the order they were applied.
    pub(crate) fn received(&self, peer: &[u8; 32]) -> Vec<String> {
        self.core
            .history(peer, None, 200)
            .into_iter()
            .filter(|m| !m.outgoing)
            .map(|m| m.text)
            .collect()
    }

    pub(crate) fn delivered(&self, peer: &[u8; 32]) -> Vec<String> {
        self.core
            .history(peer, None, 200)
            .into_iter()
            .filter(|m| m.outgoing && m.state == MsgState::Delivered)
            .map(|m| m.text)
            .collect()
    }
}

/// Send the oldest message of `from` to `to`. With `lose_ack` the sender does
/// not learn that it arrived.
fn push_one(from: &Side, to: &Side, lose_ack: bool) -> Option<AckStatus> {
    let e = from.core.outbox.first_for(&to.id())?;
    let (wire, _) = from.core.prepare_wire(&e.id).unwrap();
    let st = to.core.accept(&from.id(), &wire, 5).status;
    if st.is_delivered() && !lose_ack {
        from.core.mark_delivered(&e.id, 6);
    }
    if st == AckStatus::NoSession {
        // What the service does on that answer.
        from.core.reset_session(&to.id());
    }
    Some(st)
}

/// The catch-up of `from` towards `to` (what the service does on a new
/// connection). Returns the number of messages it closed.
pub(crate) fn catch_up(from: &Side, to: &Side) -> usize {
    let asked = sync::request_for(&from.core, &to.id());
    let have = sync::answer(&to.core, &from.id(), &asked);
    sync::apply_reply(&from.core, &to.id(), &asked, &have, 7)
}

#[test]
fn a_resend_after_a_restart_sends_the_identical_bytes() {
    let mut a = side();
    let b = side();
    let first = a.core.enqueue(&b.id(), "first", 1).unwrap();
    a.core.enqueue(&b.id(), "second", 1).unwrap();
    let (w1, env1) = a.core.prepare_wire(&first).unwrap();
    let ratchet = a.session_bytes(&b.id()).unwrap();
    // The program stops before the answer arrives.
    a.restart();
    assert_eq!(a.core.outbox.len(), 2);
    assert!(a.core.outbox.get(&first).unwrap().sealed.is_some());
    let (again, env_again) = a.core.prepare_wire(&first).unwrap();
    assert_eq!(again, w1, "the envelope must be the same bytes");
    assert_eq!(env_again, env1);
    // Sending it again did not use another key.
    assert_eq!(a.session_bytes(&b.id()).unwrap(), ratchet);
    // The receiver applies it once, however often it arrives.
    assert_eq!(b.core.accept(&a.id(), &w1, 2).status, AckStatus::Stored);
    assert_eq!(b.core.accept(&a.id(), &again, 3).status, AckStatus::Duplicate);
    a.core.mark_delivered(&first, 4);
    assert_eq!(push_one(&a, &b, false), Some(AckStatus::Stored));
    assert_eq!(b.received(&a.id()), ["first", "second"]);
    assert_eq!(a.core.outbox.sealed_bytes(), 0);
}

#[test]
fn a_resend_after_several_restarts_is_still_the_same_and_unsealed_ones_follow() {
    let mut a = side();
    let b = side();
    let ids: Vec<_> = ["one", "two", "three"]
        .iter()
        .map(|t| a.core.enqueue(&b.id(), t, 1).unwrap())
        .collect();
    let (w1, _) = a.core.prepare_wire(&ids[0]).unwrap();
    for _ in 0..3 {
        a.restart();
        assert_eq!(a.core.prepare_wire(&ids[0]).unwrap().0, w1);
    }
    assert_eq!(push_one(&a, &b, true), Some(AckStatus::Stored));
    // The ack was lost; after one more restart the same bytes are a duplicate.
    a.restart();
    assert_eq!(push_one(&a, &b, false), Some(AckStatus::Duplicate));
    for _ in 0..2 {
        assert_eq!(push_one(&a, &b, false), Some(AckStatus::Stored));
    }
    assert_eq!(b.received(&a.id()), ["one", "two", "three"]);
    assert_eq!(a.delivered(&b.id()), ["one", "two", "three"]);
}

#[test]
fn a_replaced_session_voids_the_kept_envelope_for_good() {
    let mut a = side();
    let b = side();
    let id = a.core.enqueue(&b.id(), "hello", 1).unwrap();
    let (w1, _) = a.core.prepare_wire(&id).unwrap();
    a.core.reset_session(&b.id());
    assert!(a.core.outbox.get(&id).unwrap().sealed.is_none());
    assert_eq!(a.core.outbox.sealed_bytes(), 0);
    a.restart();
    // The voided envelope does not come back from the log.
    assert!(a.core.outbox.get(&id).unwrap().sealed.is_none());
    let (w2, _) = a.core.prepare_wire(&id).unwrap();
    assert_ne!(w1, w2);
    assert_eq!(b.core.accept(&a.id(), &w2, 2).status, AckStatus::Stored);
}

#[test]
fn kept_envelopes_survive_the_log_being_rewritten() {
    let mut a = side();
    let b = side();
    let ids: Vec<_> = ["a", "b", "c"]
        .iter()
        .map(|t| a.core.enqueue(&b.id(), t, 1).unwrap())
        .collect();
    let (w0, _) = a.core.prepare_wire(&ids[0]).unwrap();
    assert_eq!(push_one(&a, &b, false), Some(AckStatus::Stored));
    let _ = w0;
    let (w1, _) = a.core.prepare_wire(&ids[1]).unwrap();
    // Opening with finished entries in the log rewrites it.
    a.restart();
    a.restart();
    assert_eq!(a.core.outbox.len(), 2);
    assert_eq!(a.core.prepare_wire(&ids[1]).unwrap().0, w1);
    assert!(a.core.outbox.get(&ids[2]).unwrap().sealed.is_none());
}

#[test]
fn an_expired_entry_leaves_no_kept_envelope_behind() {
    let dir = tempfile::tempdir().unwrap();
    let keys = Arc::new(StateKeys::from_master_key(&rand::random()).unwrap());
    let path = dir.path().join("outbox.log");
    let s = StoreSettings {
        outbox_expiry_days: 1,
        ..StoreSettings::default()
    };
    let (ob, _) = Outbox::open(&path, keys.clone(), s.clone(), 0);
    let e = super::outbox::new_entry([1; 16], [2; 32], 1, 10, "x".into());
    ob.push(e).unwrap();
    ob.set_sealed(&[1; 16], &[9; 600]).unwrap();
    assert_eq!(ob.sealed_bytes(), 600);
    drop(ob);
    let (ob, expired) = Outbox::open(&path, keys.clone(), s.clone(), 3 * 86_400_000);
    assert_eq!(expired.len(), 1);
    assert_eq!(ob.len(), 0);
    assert_eq!(ob.sealed_bytes(), 0);
    drop(ob);
    let (ob, expired) = Outbox::open(&path, keys, s, 3 * 86_400_000);
    assert!(expired.is_empty());
    assert_eq!(ob.len(), 0);
}

#[test]
fn the_kept_envelopes_are_bounded_and_refuse_before_a_key_is_used() {
    let dir = tempfile::tempdir().unwrap();
    let keys = Arc::new(StateKeys::from_master_key(&rand::random()).unwrap());
    let s = StoreSettings {
        outbox_max_per_contact: 1,
        ..StoreSettings::default()
    };
    let (ob, _) = Outbox::open(&dir.path().join("o.log"), keys, s, 1);
    let mut n = 0u32;
    while ob.has_sealed_room() {
        n += 1;
        let id = [n as u8; 16];
        let mut peer = [0u8; 32];
        peer[..4].copy_from_slice(&n.to_be_bytes());
        ob.push(super::outbox::new_entry(id, peer, 1, 1, "x".into()))
            .unwrap();
        ob.set_sealed(&id, &vec![1u8; 16 * 1024]).unwrap();
        assert!(n < 1000);
    }
    assert!(ob.sealed_bytes() <= super::outbox::SEALED_BUDGET);
    // The envelope that would not fit is refused outright.
    let id = [250; 16];
    ob.push(super::outbox::new_entry(id, [250; 32], 1, 1, "x".into()))
        .unwrap();
    let rest = super::outbox::SEALED_BUDGET - ob.sealed_bytes();
    assert!(ob.set_sealed(&id, &vec![1u8; rest + 1]).is_err());
    assert!(ob.set_sealed(&id, &[]).is_err());
}

#[test]
fn catch_up_closes_what_the_peer_has_and_leaves_the_rest() {
    let a = side();
    let b = side();
    for t in ["one", "two", "three"] {
        a.core.enqueue(&b.id(), t, 1).unwrap();
    }
    // The first two arrived, the answers were lost.
    assert_eq!(push_one(&a, &b, true), Some(AckStatus::Stored));
    // `push_one` takes the oldest, which is still the first: the second goes
    // by hand.
    let second = a.core.outbox.pending_for(&b.id())[1].clone();
    let (w, _) = a.core.prepare_wire(&second.id).unwrap();
    assert_eq!(b.core.accept(&a.id(), &w, 5).status, AckStatus::Stored);
    assert_eq!(a.core.outbox.len(), 3);
    assert_eq!(catch_up(&a, &b), 2);
    assert_eq!(a.core.outbox.len(), 1);
    assert_eq!(a.delivered(&b.id()), ["one", "two"]);
    assert_eq!(push_one(&a, &b, false), Some(AckStatus::Stored));
    assert_eq!(b.received(&a.id()), ["one", "two", "three"]);
    assert_eq!(a.delivered(&b.id()), ["one", "two", "three"]);
    // Again: nothing is left to close.
    assert_eq!(catch_up(&a, &b), 0);
}

#[test]
fn catch_up_never_closes_what_the_peer_has_not_applied() {
    let a = side();
    let b = side();
    for t in ["one", "two"] {
        a.core.enqueue(&b.id(), t, 1).unwrap();
    }
    let asked = sync::request_for(&a.core, &b.id());
    assert_eq!(asked.len(), 2);
    assert!(sync::answer(&b.core, &a.id(), &asked).is_empty());
    assert_eq!(catch_up(&a, &b), 0);
    assert_eq!(a.core.outbox.len(), 2);
    // A reply naming messages that were not asked about, or that belong to
    // another contact, closes nothing.
    let other = side();
    a.core.enqueue(&other.id(), "elsewhere", 1).unwrap();
    let elsewhere = a.core.outbox.first_for(&other.id()).unwrap().id;
    let bogus = vec![[0xEE; 16], elsewhere, asked[0].id];
    assert_eq!(sync::apply_reply(&a.core, &b.id(), &asked[1..], &bogus, 8), 0);
    assert_eq!(a.core.outbox.len(), 3);
    // The one it did ask about is closed when named.
    assert_eq!(sync::apply_reply(&a.core, &b.id(), &asked, &bogus, 8), 1);
    assert_eq!(a.core.outbox.len(), 2);
}

#[test]
fn a_message_the_peer_would_refuse_for_its_size_is_not_reported_as_had() {
    let a = side();
    let b = side_with_max(10);
    a.core.enqueue(&b.id(), "this is longer than ten bytes", 1).unwrap();
    let asked = sync::request_for(&a.core, &b.id());
    // The receiver did apply the number (it answered `TooBig`) ...
    assert_eq!(push_one(&a, &b, true), Some(AckStatus::TooBig));
    // ... but the catch-up does not call that delivered.
    assert!(sync::answer(&b.core, &a.id(), &asked).is_empty());
    // A number of 0 and an oversized claim are never "had".
    let junk = [
        SyncItem {
            id: [1; 16],
            seq: 0,
            len: 1,
        },
        SyncItem {
            id: [2; 16],
            seq: 1,
            len: 11,
        },
    ];
    assert!(sync::answer(&b.core, &a.id(), &junk).is_empty());
}

#[test]
fn a_catch_up_names_a_bounded_number_of_messages() {
    let a = side();
    let b = side();
    for i in 0..(MAX_SYNC_ITEMS + 20) {
        a.core.enqueue(&b.id(), &format!("m{i}"), 1).unwrap();
    }
    assert_eq!(sync::request_for(&a.core, &b.id()).len(), MAX_SYNC_ITEMS);
    let many: Vec<SyncItem> = (1..=500u64)
        .map(|seq| SyncItem {
            id: [seq as u8; 16],
            seq,
            len: 1,
        })
        .collect();
    // Nothing applied at the receiver: the answer is empty, and in any case
    // it never has more entries than the cap.
    assert!(sync::answer(&b.core, &a.id(), &many).len() <= MAX_SYNC_ITEMS);
}

/// A small deterministic generator, so a failure repeats.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self, n: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) % n
    }
}

#[test]
fn both_sides_converge_after_interleaved_offline_periods() {
    for seed in 1..=6u64 {
        let mut rng = Lcg(seed);
        let mut a = side();
        let mut b = side();
        let (mut sent_a, mut sent_b) = (Vec::new(), Vec::new());
        for step in 0..80 {
            match rng.next(8) {
                0 | 1 => {
                    let t = format!("a{step}");
                    a.core.enqueue(&b.id(), &t, 1).unwrap();
                    sent_a.push(t);
                }
                2 => {
                    let t = format!("b{step}");
                    b.core.enqueue(&a.id(), &t, 1).unwrap();
                    sent_b.push(t);
                }
                // One send whose answer is lost, either way.
                3 => {
                    push_one(&a, &b, true);
                }
                4 => {
                    push_one(&b, &a, true);
                }
                5 => a.restart(),
                6 => b.restart(),
                // A short online period.
                _ => {
                    catch_up(&a, &b);
                    catch_up(&b, &a);
                    push_one(&a, &b, false);
                    push_one(&b, &a, false);
                }
            }
        }
        // Back online for good.
        for _ in 0..4 {
            catch_up(&a, &b);
            catch_up(&b, &a);
            for _ in 0..200 {
                if a.core.outbox.is_empty() && b.core.outbox.is_empty() {
                    break;
                }
                push_one(&a, &b, false);
                push_one(&b, &a, false);
            }
        }
        assert_eq!(a.core.outbox.len(), 0, "seed {seed}");
        assert_eq!(b.core.outbox.len(), 0, "seed {seed}");
        let mut got_b = b.received(&a.id());
        let mut got_a = a.received(&b.id());
        // Everything arrived exactly once.
        assert_eq!(got_b.len(), sent_a.len(), "seed {seed}");
        assert_eq!(got_a.len(), sent_b.len(), "seed {seed}");
        got_b.sort();
        got_a.sort();
        sent_a.sort();
        sent_b.sort();
        assert_eq!(got_b, sent_a, "seed {seed}");
        assert_eq!(got_a, sent_b, "seed {seed}");
        // Both ends agree on what was delivered.
        let mut d_a = a.delivered(&b.id());
        d_a.sort();
        assert_eq!(d_a, sent_a, "seed {seed}");
        assert_eq!(a.core.outbox.sealed_bytes(), 0);
    }
}

#[test]
fn a_flood_of_resends_does_not_grow_the_kept_state() {
    // The same few messages are sealed, lost, restarted and caught up over and
    // over: the kept bytes and the log stay at the size of the pending set.
    let mut a = side();
    let b = side();
    let log = crate::paths::chat_outbox_file(&a.dir.path().join("chat"));
    let mut max_sealed = 0;
    let mut max_log = 0;
    for round in 0..300u32 {
        a.core.enqueue(&b.id(), &format!("m{round}"), 1).unwrap();
        push_one(&a, &b, true);
        if round % 7 == 0 {
            a.restart();
        }
        catch_up(&a, &b);
        max_sealed = max_sealed.max(a.core.outbox.sealed_bytes());
        max_log = max_log.max(std::fs::metadata(&log).map(|m| m.len()).unwrap_or(0));
    }
    assert_eq!(a.core.outbox.len(), 0);
    assert!(max_sealed <= 16 * 1024, "{max_sealed}");
    assert!(max_log < 1024 * 1024, "{max_log}");
}

#[test]
fn the_catch_up_leaves_read_receipts_alone() {
    let a = side();
    let b = side();
    b.core.set_receipt_interval_ms(0);
    for t in ["one", "two"] {
        a.core.enqueue(&b.id(), t, 1).unwrap();
        assert_eq!(push_one(&a, &b, false), Some(AckStatus::Stored));
    }
    b.core.mark_read(&a.id(), 2, 100).unwrap();
    assert_eq!(b.core.outbox.len(), 1, "a receipt waits at b");
    // A receipt is not a message with a number of its own: it is not named,
    // and so nothing about it can be closed by the answer.
    assert!(sync::request_for(&b.core, &a.id()).is_empty());
    assert_eq!(catch_up(&b, &a), 0);
    assert_eq!(b.core.outbox.len(), 1);
}
