//! Tests of read receipts at the engine level: two engines hand envelopes to
//! each other directly.

use std::sync::Arc;

use super::{
    engine::{EventKind, MarkOutcome},
    engine_tests::{deliver_next, side, side_with, Side},
    outbox::{new_receipt, OutKind, Outbox},
    proto::AckStatus,
    store::{MsgState, StoreSettings},
};
use crate::state_crypto::StateKeys;

/// `a` sends `n` texts to `b`, all delivered.
fn send_texts(a: &Side, b: &Side, n: usize) {
    for i in 0..n {
        a.core.enqueue(&b.id(), &format!("text {i}"), 1).unwrap();
        assert_eq!(deliver_next(a, b), Some(AckStatus::Stored));
    }
}

fn states(a: &Side, b: &Side) -> Vec<MsgState> {
    a.core
        .history(&b.id(), None, 200)
        .into_iter()
        .filter(|m| m.outgoing)
        .map(|m| m.state)
        .collect()
}

fn fast_receipts(s: &Side) {
    s.core.set_receipt_interval_ms(0);
}

#[test]
fn both_sides_on_a_read_receipt_marks_the_messages_read() {
    let a = side();
    let b = side();
    fast_receipts(&b);
    send_texts(&a, &b, 3);
    assert_eq!(states(&a, &b), [MsgState::Delivered; 3]);
    // Nothing is sent just because the messages arrived.
    assert!(b.core.outbox.is_empty());

    assert_eq!(
        b.core.mark_read(&a.id(), 3, 100).unwrap(),
        MarkOutcome::Queued
    );
    assert_eq!(b.core.outbox.len(), 1);
    assert_eq!(deliver_next(&b, &a), Some(AckStatus::Stored));
    assert!(b.core.outbox.is_empty());
    assert_eq!(states(&a, &b), [MsgState::Read; 3]);

    // It is an event for a client, and no message anywhere.
    let (_, ev) = a.core.events_since(0);
    let reads: Vec<_> = ev.iter().filter(|e| e.kind == EventKind::Read).collect();
    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0].message.seq, 3);
    assert_eq!(a.texts(&b.id()).len(), 3);
    assert_eq!(b.texts(&a.id()).len(), 3);
    assert!(a.core.outbox.is_empty());
}

#[test]
fn only_the_messages_up_to_the_number_are_read() {
    let a = side();
    let b = side();
    fast_receipts(&b);
    send_texts(&a, &b, 4);
    assert_eq!(
        b.core.mark_read(&a.id(), 2, 100).unwrap(),
        MarkOutcome::Queued
    );
    deliver_next(&b, &a);
    assert_eq!(
        states(&a, &b),
        [
            MsgState::Read,
            MsgState::Read,
            MsgState::Delivered,
            MsgState::Delivered
        ]
    );
    // A number beyond what arrived is cut down to what arrived.
    assert_eq!(
        b.core.mark_read(&a.id(), u64::MAX, 200).unwrap(),
        MarkOutcome::Queued
    );
    assert_eq!(b.core.outbox.receipt_for(&a.id()).unwrap().seq, 4);
    deliver_next(&b, &a);
    assert_eq!(states(&a, &b), [MsgState::Read; 4]);
}

#[test]
fn the_receiving_side_off_sends_nothing() {
    let a = side();
    let b = side();
    fast_receipts(&b);
    send_texts(&a, &b, 2);
    b.core.set_receipts(&a.id(), false).unwrap();
    assert!(!b.core.receipts_enabled(&a.id()));
    assert_eq!(
        b.core.mark_read(&a.id(), 2, 100).unwrap(),
        MarkOutcome::Disabled
    );
    assert!(b.core.outbox.is_empty());
    assert_eq!(states(&a, &b), [MsgState::Delivered; 2]);
    // The global switch has the same effect.
    let c = side();
    fast_receipts(&c);
    send_texts(&a, &c, 1);
    c.core.set_receipts_global(false);
    assert_eq!(
        c.core.mark_read(&a.id(), 1, 100).unwrap(),
        MarkOutcome::Disabled
    );
    assert!(c.core.outbox.is_empty());
}

#[test]
fn the_sending_side_off_hides_what_arrives_and_keeps_none() {
    let a = side();
    let b = side();
    fast_receipts(&b);
    send_texts(&a, &b, 2);
    a.core.set_receipts(&b.id(), false).unwrap();
    assert_eq!(
        b.core.mark_read(&a.id(), 2, 100).unwrap(),
        MarkOutcome::Queued
    );
    // The receipt is accepted (so the other side can finish with it) ...
    assert_eq!(deliver_next(&b, &a), Some(AckStatus::Stored));
    // ... but it is hidden, and no event tells a client about it.
    assert_eq!(states(&a, &b), [MsgState::Delivered; 2]);
    assert!(a
        .core
        .events_since(0)
        .1
        .iter()
        .all(|e| e.kind != EventKind::Read));
    // Switching it on again does not bring back what was dropped.
    a.core.set_receipts(&b.id(), true).unwrap();
    assert_eq!(states(&a, &b), [MsgState::Delivered; 2]);
    // Receipts that arrive from now on show.
    send_texts(&a, &b, 1);
    assert_eq!(
        b.core.mark_read(&a.id(), 3, 200).unwrap(),
        MarkOutcome::Queued
    );
    deliver_next(&b, &a);
    assert_eq!(states(&a, &b), [MsgState::Read; 3]);
    // Switching off hides what was already shown.
    a.core.set_receipts_global(false);
    assert_eq!(states(&a, &b), [MsgState::Delivered; 3]);
}

#[test]
fn switching_a_contact_off_drops_the_receipt_still_waiting() {
    let a = side();
    let b = side();
    fast_receipts(&b);
    send_texts(&a, &b, 1);
    b.core.mark_read(&a.id(), 1, 100).unwrap();
    assert_eq!(b.core.outbox.len(), 1);
    b.core.set_receipts(&a.id(), false).unwrap();
    assert!(b.core.outbox.is_empty());
}

#[test]
fn a_receipt_twice_changes_nothing() {
    let a = side();
    let b = side();
    fast_receipts(&b);
    send_texts(&a, &b, 2);
    b.core.mark_read(&a.id(), 2, 100).unwrap();
    let e = b.core.outbox.first_for(&a.id()).unwrap();
    let (wire, _) = b.core.prepare_wire(&e.id).unwrap();
    assert_eq!(a.core.accept(&b.id(), &wire, 5).status, AckStatus::Stored);
    // The retry after a lost acknowledgement, in this process and after a restart.
    assert_eq!(
        a.core.accept(&b.id(), &wire, 6).status,
        AckStatus::Duplicate
    );
    let mut a = a;
    a.restart();
    assert_eq!(
        a.core.accept(&b.id(), &wire, 7).status,
        AckStatus::Duplicate
    );
    assert_eq!(states(&a, &b), [MsgState::Read; 2]);
    // Reporting the same point again is nothing, not a second receipt.
    assert_eq!(
        b.core.mark_read(&a.id(), 2, 200).unwrap(),
        MarkOutcome::Nothing
    );
    // A receipt for an older point arriving late does not move it back.
    send_texts(&a, &b, 1);
    b.core.mark_read(&a.id(), 3, 9_000).unwrap();
    deliver_next(&b, &a);
    assert_eq!(states(&a, &b), [MsgState::Read; 3]);
    assert_eq!(
        a.core.accept(&b.id(), &wire, 9).status,
        AckStatus::Duplicate
    );
    assert_eq!(states(&a, &b), [MsgState::Read; 3]);
}

#[test]
fn a_receipt_never_creates_a_receipt_or_a_message() {
    let a = side();
    let b = side();
    fast_receipts(&a);
    fast_receipts(&b);
    send_texts(&a, &b, 2);
    b.core.mark_read(&a.id(), 2, 100).unwrap();
    deliver_next(&b, &a);
    // a received only a receipt: nothing to report, nothing queued, nothing
    // in the history, and no "received" event.
    assert!(a.core.outbox.is_empty());
    assert_eq!(
        a.core.mark_read(&b.id(), 99, 200).unwrap(),
        MarkOutcome::Nothing
    );
    assert!(a.core.outbox.is_empty());
    assert_eq!(a.texts(&b.id()).len(), 2);
    assert!(a
        .core
        .events_since(0)
        .1
        .iter()
        .all(|e| e.kind != EventKind::Received));
    // And b never got a Received-style record for the receipt either.
    assert_eq!(b.texts(&a.id()).len(), 2);
    assert!(b.core.outbox.is_empty());
}

#[test]
fn a_receipt_that_claims_more_than_was_sent_is_ignored() {
    let a = side();
    let b = side();
    send_texts(&a, &b, 2);
    b.core
        .outbox
        .push_receipt(new_receipt(rand::random(), a.id(), 99, 1))
        .unwrap();
    assert_eq!(deliver_next(&b, &a), Some(AckStatus::Stored));
    assert_eq!(states(&a, &b), [MsgState::Delivered; 2]);
}

#[test]
fn receipts_are_limited_in_rate_and_coalesced_into_one() {
    let a = side();
    let b = side();
    send_texts(&a, &b, 1);
    assert_eq!(
        b.core.mark_read(&a.id(), 1, 10_000).unwrap(),
        MarkOutcome::Queued
    );
    send_texts(&a, &b, 1);
    // Too soon after the last one: the caller may ask again later.
    assert_eq!(
        b.core.mark_read(&a.id(), 2, 11_000).unwrap(),
        MarkOutcome::TooSoon
    );
    assert_eq!(b.core.outbox.len(), 1);
    // Later, the waiting receipt (not yet delivered) is replaced by the
    // newer one: one receipt per contact, never a pile.
    assert_eq!(
        b.core.mark_read(&a.id(), 2, 16_000).unwrap(),
        MarkOutcome::Queued
    );
    assert_eq!(b.core.outbox.len(), 1);
    assert_eq!(b.core.outbox.receipt_for(&a.id()).unwrap().seq, 2);
    // Receipts do not use up the room for messages.
    assert_eq!(b.core.outbox.text_len(), 0);
    assert_eq!(b.core.outbox.count_for(&a.id()), 0);
    assert!(b
        .core
        .history(&a.id(), None, 50)
        .iter()
        .all(|m| m.state != MsgState::Queued));
}

#[test]
fn a_receipt_has_the_wire_size_of_a_short_text() {
    let a = side();
    let b = side();
    fast_receipts(&b);
    send_texts(&a, &b, 1);
    // b's first message to a, then a receipt, then a text, in one chain:
    // all three are the same number of bytes. A longer text goes into the
    // next padding bucket, which a receipt never needs.
    let first = b.core.enqueue(&a.id(), "short", 1).unwrap();
    let w_text = b.core.prepare_wire(&first).unwrap().0;
    b.core.mark_read(&a.id(), 1, 100).unwrap();
    let r = b.core.outbox.receipt_for(&a.id()).unwrap();
    let w_receipt = b.core.prepare_wire(&r.id).unwrap().0;
    let second = b.core.enqueue(&a.id(), &"あ".repeat(100), 2).unwrap();
    let w_text2 = b.core.prepare_wire(&second).unwrap().0;
    let big = b.core.enqueue(&a.id(), &"x".repeat(900), 3).unwrap();
    let w_big = b.core.prepare_wire(&big).unwrap().0;
    assert_eq!(w_text.len(), w_receipt.len());
    assert_eq!(w_text.len(), w_text2.len());
    assert!(w_big.len() > w_receipt.len());
    // Padding is in the encrypted body: the ciphertext is exactly a bucket
    // plus the tag.
    for w in [&w_text, &w_receipt] {
        let env = super::crypto::Envelope::decode(w).unwrap();
        assert!(
            super::crypto::PAD_BUCKETS.contains(&(env.ciphertext.len() - super::crypto::TAG_LEN))
        );
    }
}

#[test]
fn a_receipt_and_the_switches_survive_a_restart() {
    let mut a = side();
    let mut b = side();
    fast_receipts(&b);
    send_texts(&a, &b, 2);
    b.core.set_receipts(&a.id(), true).unwrap();
    b.core.mark_read(&a.id(), 2, 100).unwrap();
    // The receipt waits across a restart of the sender of the receipt.
    b.restart();
    let waiting = b.core.outbox.receipt_for(&a.id()).expect("kept");
    assert_eq!(waiting.kind, OutKind::Read);
    assert_eq!(waiting.seq, 2);
    // It is not queued again for the same point.
    assert_eq!(
        b.core.mark_read(&a.id(), 2, 5_000).unwrap(),
        MarkOutcome::Nothing
    );
    assert_eq!(deliver_next(&b, &a), Some(AckStatus::Stored));
    // What was learned persists.
    a.restart();
    assert_eq!(states(&a, &b), [MsgState::Read; 2]);
    // A switch persists too.
    a.core.set_receipts(&b.id(), false).unwrap();
    a.restart();
    assert!(!a.core.receipts_enabled(&b.id()));
    assert_eq!(states(&a, &b), [MsgState::Delivered; 2]);
}

#[test]
fn a_receipt_that_expired_is_dropped_not_failed() {
    let dir = tempfile::tempdir().unwrap();
    let keys = Arc::new(StateKeys::from_master_key(&rand::random()).unwrap());
    let s = StoreSettings {
        receipt_expiry_ms: 60_000,
        ..StoreSettings::default()
    };
    let path = dir.path().join("outbox.log");
    let peer = [3u8; 32];
    {
        let (ob, expired) = Outbox::open(&path, keys.clone(), s.clone(), 1_000);
        assert!(expired.is_empty());
        ob.push_receipt(new_receipt(rand::random(), peer, 7, 1_000))
            .unwrap();
        // A message queued at the same time.
        ob.push(super::outbox::new_entry(
            rand::random(),
            peer,
            1,
            1_000,
            "hello".into(),
        ))
        .unwrap();
        assert_eq!(ob.len(), 2);
    }
    // Reopened before the expiry: both are still there.
    {
        let (ob, expired) = Outbox::open(&path, keys.clone(), s.clone(), 30_000);
        assert!(expired.is_empty());
        assert_eq!(ob.len(), 2);
        assert_eq!(ob.receipt_for(&peer).unwrap().seq, 7);
    }
    // Reopened after it: the receipt is gone and is not reported as a failed
    // message; the text (30 days) is untouched.
    let (ob, expired) = Outbox::open(&path, keys, s, 120_000);
    assert!(expired.is_empty());
    assert_eq!(ob.len(), 1);
    assert!(ob.receipt_for(&peer).is_none());
    assert_eq!(ob.text_len(), 1);
}

#[test]
fn a_running_engine_knows_when_a_receipt_has_expired() {
    let s = StoreSettings {
        receipt_expiry_ms: 1_000,
        ..StoreSettings::default()
    };
    let a = side();
    let b = side_with(s, 4096);
    fast_receipts(&b);
    send_texts(&a, &b, 1);
    b.core.mark_read(&a.id(), 1, 10_000).unwrap();
    let e = b.core.outbox.receipt_for(&a.id()).unwrap();
    assert!(!b.core.receipt_expired(&e, 10_500));
    assert!(b.core.receipt_expired(&e, 12_000));
    // A message never expires through this check.
    let t = b.core.enqueue(&a.id(), "t", 10_000).unwrap();
    let te = b.core.outbox.get(&t).unwrap();
    assert!(!b.core.receipt_expired(&te, 99_999_999));
}

#[test]
fn a_failed_receipt_leaves_no_trace_in_the_history() {
    let a = side();
    let b = side();
    fast_receipts(&b);
    send_texts(&a, &b, 1);
    b.core.mark_read(&a.id(), 1, 100).unwrap();
    let e = b.core.outbox.receipt_for(&a.id()).unwrap();
    b.core.mark_failed(&e.id, "not_allowed", 200);
    assert!(b.core.outbox.is_empty());
    assert!(b
        .core
        .history(&a.id(), None, 50)
        .iter()
        .all(|m| !m.outgoing));
    assert!(b
        .core
        .events_since(0)
        .1
        .iter()
        .all(|e| e.kind != EventKind::Failed));
}
