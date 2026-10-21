//! Tests of what happens when the data of one side is put back to an earlier
//! copy (a restored backup, a copied folder): two engines hand envelopes to
//! each other directly, one of them has its whole chat folder replaced by a
//! copy taken earlier, and the conversation goes on.
//!
//! The tests state what this build does today. Where a result is a known
//! limit that a later change is meant to remove, the expected value hangs on
//! a named constant, so the test is flipped in one place.

use std::{fs, path::Path};

use tempfile::TempDir;

use super::{
    crypto::Envelope,
    engine::MarkOutcome,
    engine_tests::{deliver_next, open_core, side, Side},
    proto::AckStatus,
    store::{MsgState, StoreSettings},
};

/// The answer to an envelope that cannot be opened and does not start a
/// session (every sender since beta.2 starts a new session on it).
const UNOPENABLE_ANSWER: AckStatus = AckStatus::NoSession;

/// True once a message sent from a restored copy no longer repeats a number
/// the receiver already applied (the receiver then keeps the message).
const SEND_NUMBER_REUSE_CLOSED: bool = false;

/// True once a message sent from a restored copy no longer repeats the
/// position (ratchet key and index) of an envelope sent before.
const POSITION_REUSE_CLOSED: bool = false;

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap().flatten() {
        let (p, t) = (e.path(), to.join(e.file_name()));
        if p.is_dir() {
            copy_tree(&p, &t);
        } else {
            fs::copy(&p, &t).unwrap();
        }
    }
}

/// A copy of the whole chat folder of one side.
struct Snapshot(TempDir);

fn snapshot(s: &mut Side) -> Snapshot {
    // Everything is settled on disk first.
    s.restart();
    let d = tempfile::tempdir().unwrap();
    copy_tree(&s.dir.path().join("chat"), d.path());
    Snapshot(d)
}

/// Put the chat folder back to the copy and open it again.
fn rollback(s: &mut Side, snap: &Snapshot) {
    s.core.store.close();
    // Release the files of the running engine before they are replaced.
    let scratch = tempfile::tempdir().unwrap();
    s.core = open_core(
        scratch.path(),
        &s.seed,
        &s.master,
        StoreSettings::default(),
        4096,
    );
    let chat = s.dir.path().join("chat");
    fs::remove_dir_all(&chat).unwrap();
    copy_tree(snap.0.path(), &chat);
    s.restart();
}

/// Send the oldest queued item of `from`; the envelope and the answer.
fn send_one(from: &Side, to: &Side) -> (Vec<u8>, AckStatus) {
    let e = from
        .core
        .outbox
        .first_for(&to.id())
        .expect("something queued");
    let (wire, _) = from.core.prepare_wire(&e.id).unwrap();
    let st = to.core.accept(&from.id(), &wire, 5).status;
    if st.is_delivered() {
        from.core.mark_delivered(&e.id, 6);
    }
    (wire, st)
}

fn position(wire: &[u8]) -> ([u8; 32], u32) {
    let h = Envelope::decode(wire).unwrap().header;
    (h.dh_pub, h.n)
}

/// `first` writes, `second` answers; both have a session afterwards.
fn establish(first: &Side, second: &Side) {
    first.core.enqueue(&second.id(), "hello", 1).unwrap();
    assert_eq!(deliver_next(first, second), Some(AckStatus::Stored));
    second.core.enqueue(&first.id(), "hello back", 1).unwrap();
    assert_eq!(deliver_next(second, first), Some(AckStatus::Stored));
}

/// `victim` tells `other` that it read something (this moves the ratchet but
/// uses no message number).
fn read_and_tell(victim: &Side, other: &Side, up_to: u64, at: u64) -> Vec<u8> {
    assert_eq!(
        victim.core.mark_read(&other.id(), up_to, at).unwrap(),
        MarkOutcome::Queued
    );
    let (wire, st) = send_one(victim, other);
    assert_eq!(st, AckStatus::Stored);
    wire
}

/// The common course: `victim` takes a copy, then the two exchange a receipt,
/// a text and another receipt (so both ratchets move twice), then the copy is
/// put back. Returns the envelope of the first receipt, which used the
/// position that the restored side will use next.
fn restore_across_ratchet_steps(
    first: &mut Side,
    second: &mut Side,
    victim_is_first: bool,
) -> Vec<u8> {
    establish(first, second);
    let (victim, other) = if victim_is_first {
        (first, second)
    } else {
        (second, first)
    };
    let snap = snapshot(victim);
    let used = read_and_tell(victim, other, 1, 1_000_000);
    other
        .core
        .enqueue(&victim.id(), "while you were away", 2)
        .unwrap();
    assert_eq!(deliver_next(other, victim), Some(AckStatus::Stored));
    read_and_tell(victim, other, 2, 2_000_000);
    rollback(victim, &snap);
    used
}

/// Texts `side` received from `peer`, in the order they were applied.
fn received(side: &Side, peer: &[u8; 32]) -> Vec<String> {
    side.core
        .history(peer, None, 200)
        .into_iter()
        .filter(|m| !m.outgoing)
        .map(|m| m.text)
        .collect()
}

fn nothing_failed(side: &Side, peer: &[u8; 32]) -> bool {
    side.core
        .history(peer, None, 200)
        .iter()
        .all(|m| m.state != MsgState::Failed)
}

#[test]
fn a_conversation_stopped_by_a_restore_across_ratchet_steps_starts_again_for_the_initiator() {
    let (mut a, mut b) = (side(), side());
    let used = restore_across_ratchet_steps(&mut a, &mut b, true);
    let (peer_b, peer_a) = (b.id(), a.id());
    // The restored side has three messages waiting. The first reuses the
    // position of the receipt it sent before the restore.
    for t in ["q1", "q2", "q3"] {
        a.core.enqueue(&peer_b, t, 3).unwrap();
    }
    let (wire, st) = send_one(&a, &b);
    assert_eq!(position(&wire) == position(&used), !POSITION_REUSE_CLOSED);
    assert_eq!(st, UNOPENABLE_ANSWER);
    // What the service does on that answer: a new session, the same message.
    a.core.reset_session(&peer_b);
    for _ in 0..3 {
        assert_eq!(send_one(&a, &b).1, AckStatus::Stored);
    }
    assert!(a.core.outbox.first_for(&peer_b).is_none());
    // In order, after the text that came before the copy was taken.
    assert_eq!(received(&b, &peer_a), ["hello", "q1", "q2", "q3"]);
    assert!(nothing_failed(&a, &peer_b));
    // The other direction works on the new session.
    b.core.enqueue(&peer_a, "from the other side", 4).unwrap();
    assert_eq!(send_one(&b, &a).1, AckStatus::Stored);
    assert!(received(&a, &peer_b).contains(&"from the other side".to_string()));
}

#[test]
fn a_conversation_stopped_by_a_restore_across_ratchet_steps_starts_again_for_the_responder() {
    let (mut a, mut b) = (side(), side());
    let used = restore_across_ratchet_steps(&mut a, &mut b, false);
    let (peer_b, peer_a) = (b.id(), a.id());
    // `b` is the restored side here and `a` writes first.
    a.core.enqueue(&peer_b, "from the other side", 3).unwrap();
    let (_, st) = send_one(&a, &b);
    assert_eq!(st, UNOPENABLE_ANSWER);
    a.core.reset_session(&peer_b);
    assert_eq!(send_one(&a, &b).1, AckStatus::Stored);
    // The restored side replaces its session and writes on the new one.
    b.core.enqueue(&peer_a, "after the restore", 4).unwrap();
    let (wire, st) = send_one(&b, &a);
    assert_ne!(
        position(&wire),
        position(&used),
        "a new session, a new position"
    );
    assert_eq!(st, AckStatus::Stored);
    assert!(received(&a, &peer_b).contains(&"after the restore".to_string()));
    assert!(received(&b, &peer_a).contains(&"from the other side".to_string()));
    assert!(nothing_failed(&a, &peer_b) && nothing_failed(&b, &peer_a));
}

#[test]
fn an_envelope_that_does_not_open_gets_no_session_and_changes_nothing() {
    let (a, b) = (side(), side());
    establish(&a, &b);
    a.core.enqueue(&b.id(), "second", 2).unwrap();
    let e = a.core.outbox.first_for(&b.id()).unwrap();
    let (wire, _) = a.core.prepare_wire(&e.id).unwrap();
    let mut damaged = wire.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 0x01;
    let state = |s: &Side| {
        s.core.store.peek_peer(&a.id(), |st| {
            st.session.as_ref().map(|x| x.to_bytes().to_vec())
        })
    };
    let before = state(&b);
    assert_eq!(
        b.core.accept(&a.id(), &damaged, 3).status,
        AckStatus::NoSession
    );
    let mut handled = false;
    let st = b.core.accept_raw(&a.id(), &damaged, |_| {
        handled = true;
        AckStatus::Stored
    });
    assert_eq!(st, AckStatus::NoSession);
    assert!(
        !handled,
        "nothing is handed over for a message that did not open"
    );
    assert_eq!(state(&b), before);
    // The genuine envelope still opens.
    assert_eq!(b.core.accept(&a.id(), &wire, 4).status, AckStatus::Stored);
    // A first message that does not open is still a bad request: nothing is
    // known about the sender yet, so there is nothing to start again.
    let c = side();
    c.core.enqueue(&b.id(), "hello", 1).unwrap();
    let e = c.core.outbox.first_for(&b.id()).unwrap();
    let (first, _) = c.core.prepare_wire(&e.id).unwrap();
    let mut bad_first = first.clone();
    let last = bad_first.len() - 1;
    bad_first[last] ^= 0x01;
    assert_eq!(
        b.core.accept(&c.id(), &bad_first, 5).status,
        AckStatus::BadRequest
    );
    assert_eq!(b.core.accept(&c.id(), &first, 6).status, AckStatus::Stored);
}

#[test]
fn a_restore_on_the_same_chain_repeats_positions_one_message_at_a_time() {
    let (mut a, b) = (side(), side());
    establish(&a, &b);
    let snap = snapshot(&mut a);
    // Three messages leave and arrive, then the copy is put back.
    let mut used = Vec::new();
    for t in ["t1", "t2", "t3"] {
        a.core.enqueue(&b.id(), t, 2).unwrap();
        let (wire, st) = send_one(&a, &b);
        assert_eq!(st, AckStatus::Stored);
        used.push(position(&wire));
    }
    rollback(&mut a, &snap);
    // Every new message takes a position that was used; the receiver cannot
    // open it. A failed message is given up by the sender, so the next one
    // takes the next position, until the positions pass the receiver's.
    let mut answers = Vec::new();
    for t in ["q1", "q2", "q3", "q4"] {
        let id = a.core.enqueue(&b.id(), t, 3).unwrap();
        let (wire, st) = send_one(&a, &b);
        if answers.len() < 3 {
            assert_eq!(
                used.contains(&position(&wire)),
                !POSITION_REUSE_CLOSED,
                "{t}"
            );
        }
        if st == UNOPENABLE_ANSWER {
            a.core.mark_failed(&id, "rejected", 4);
        }
        answers.push(st);
    }
    assert_eq!(
        answers,
        [
            UNOPENABLE_ANSWER,
            UNOPENABLE_ANSWER,
            UNOPENABLE_ANSWER,
            AckStatus::Stored
        ]
    );
}

#[test]
fn a_send_number_taken_back_by_a_restore_is_used_again_and_the_receiver_drops_the_message() {
    let (mut a, b) = (side(), side());
    establish(&a, &b);
    a.core.enqueue(&b.id(), "one", 2).unwrap();
    assert_eq!(deliver_next(&a, &b), Some(AckStatus::Stored));
    let snap = snapshot(&mut a);
    a.core.enqueue(&b.id(), "two", 3).unwrap();
    assert_eq!(deliver_next(&a, &b), Some(AckStatus::Stored));
    rollback(&mut a, &snap);
    // A fresh session, so that the envelope opens and only the number is
    // in question.
    a.core.reset_session(&b.id());
    a.core.enqueue(&b.id(), "three", 4).unwrap();
    let (_, st) = send_one(&a, &b);
    let kept = b.texts(&a.id()).contains(&"three".to_string());
    assert_eq!(kept, SEND_NUMBER_REUSE_CLOSED);
    if !SEND_NUMBER_REUSE_CLOSED {
        // The receiver drops it and the sender shows it as delivered.
        assert_eq!(st, AckStatus::Duplicate);
        let shown_delivered = a
            .core
            .history(&b.id(), None, 200)
            .iter()
            .any(|m| m.outgoing && m.text == "three" && m.state == MsgState::Delivered);
        assert!(shown_delivered);
    }
}
