//! Tests of what happens when the data of one side is put back to an earlier
//! copy (a restored backup, a copied folder): two engines hand envelopes to
//! each other directly, one of them has its whole chat folder replaced by a
//! copy taken earlier, and the conversation goes on.
//!
//! The record kept outside the chat folder (see [`super::anchor`]) lets a
//! side notice that its session file is older than the last one it wrote. The
//! tests show what that closes (a partial restore: only the chat folder goes
//! back) and what it cannot close (a full restore: the chat folder and the
//! record go back together, or the record is gone). The limits are asserted,
//! so a change that moves them shows up here.

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

/// A copy of the whole chat folder of one side, and of its anchor folder.
struct Snapshot {
    chat: TempDir,
    anchor: TempDir,
}

fn snapshot(s: &mut Side) -> Snapshot {
    // Everything is settled on disk first.
    s.restart();
    let chat = tempfile::tempdir().unwrap();
    copy_tree(&s.dir.path().join("chat"), chat.path());
    let anchor = tempfile::tempdir().unwrap();
    copy_tree(s.anchor.path(), anchor.path());
    Snapshot { chat, anchor }
}

/// What a restore of the data does to the record outside it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Record {
    /// The record stays as it is (only the data folder was put back).
    Kept,
    /// The record is put back together with the data folder.
    PutBack,
    /// The record is gone.
    Removed,
}

/// Put the chat folder back to the copy and open it again.
fn rollback_with(s: &mut Side, snap: &Snapshot, record: Record) {
    s.core.store.close();
    // Release the files of the running engine before they are replaced.
    let scratch = tempfile::tempdir().unwrap();
    s.core = open_core(
        scratch.path(),
        None,
        &s.seed,
        &s.master,
        StoreSettings::default(),
        4096,
    );
    let chat = s.dir.path().join("chat");
    fs::remove_dir_all(&chat).unwrap();
    copy_tree(snap.chat.path(), &chat);
    match record {
        Record::Kept => {}
        Record::PutBack => {
            fs::remove_dir_all(s.anchor.path()).unwrap();
            copy_tree(snap.anchor.path(), s.anchor.path());
        }
        Record::Removed => {
            fs::remove_dir_all(s.anchor.path()).unwrap();
            fs::create_dir_all(s.anchor.path()).unwrap();
        }
    }
    s.restart();
}

fn rollback(s: &mut Side, snap: &Snapshot) {
    rollback_with(s, snap, Record::Kept);
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
/// position that the restored side will use next, and the copy.
fn restore_across_ratchet_steps(
    first: &mut Side,
    second: &mut Side,
    victim_is_first: bool,
    record: Record,
) -> (Vec<u8>, Snapshot) {
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
    rollback_with(victim, &snap, record);
    (used, snap)
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

// ── What the record closes: only the chat folder goes back ───────────────────

#[test]
fn a_restore_across_ratchet_steps_starts_a_new_session_before_anything_is_sent() {
    let (mut a, mut b) = (side(), side());
    let (used, _) = restore_across_ratchet_steps(&mut a, &mut b, true, Record::Kept);
    let (peer_b, peer_a) = (b.id(), a.id());
    // The restored side has three messages waiting. The first would have
    // reused the position of the receipt it sent before the restore; the
    // session was dropped when the file was found older, so it does not.
    for t in ["q1", "q2", "q3"] {
        a.core.enqueue(&peer_b, t, 3).unwrap();
    }
    let (wire, st) = send_one(&a, &b);
    assert_ne!(position(&wire), position(&used));
    assert_eq!(st, AckStatus::Stored, "a first message of a new session");
    for _ in 0..2 {
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
fn a_restore_across_ratchet_steps_starts_again_for_the_responder() {
    let (mut a, mut b) = (side(), side());
    let (used, _) = restore_across_ratchet_steps(&mut a, &mut b, false, Record::Kept);
    let (peer_b, peer_a) = (b.id(), a.id());
    // `b` is the restored side here and `a` writes first.
    a.core.enqueue(&peer_b, "from the other side", 3).unwrap();
    let (_, st) = send_one(&a, &b);
    // `b` dropped its session; what `a` sends on the old one does not open.
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
fn a_restore_on_the_same_chain_does_not_repeat_positions() {
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
    // Every new message takes a position that was not used, and the receiver
    // opens it at once.
    for t in ["q1", "q2", "q3", "q4"] {
        a.core.enqueue(&b.id(), t, 3).unwrap();
        let (wire, st) = send_one(&a, &b);
        assert!(!used.contains(&position(&wire)), "{t}");
        assert_eq!(st, AckStatus::Stored, "{t}");
    }
    assert_eq!(
        received(&b, &a.id()),
        ["hello", "t1", "t2", "t3", "q1", "q2", "q3", "q4"]
    );
}

#[test]
fn a_send_number_taken_back_by_a_restore_is_not_used_again() {
    let (mut a, b) = (side(), side());
    establish(&a, &b);
    a.core.enqueue(&b.id(), "one", 2).unwrap();
    assert_eq!(deliver_next(&a, &b), Some(AckStatus::Stored));
    let snap = snapshot(&mut a);
    a.core.enqueue(&b.id(), "two", 3).unwrap();
    assert_eq!(deliver_next(&a, &b), Some(AckStatus::Stored));
    rollback(&mut a, &snap);
    a.core.enqueue(&b.id(), "three", 4).unwrap();
    let (_, st) = send_one(&a, &b);
    assert_eq!(st, AckStatus::Stored);
    assert!(b.texts(&a.id()).contains(&"three".to_string()));
    let shown_delivered = a
        .core
        .history(&b.id(), None, 200)
        .iter()
        .any(|m| m.outgoing && m.text == "three" && m.state == MsgState::Delivered);
    assert!(shown_delivered);
}

#[test]
fn only_the_session_file_going_back_is_caught_too() {
    let (mut a, b) = (side(), side());
    establish(&a, &b);
    let snap = snapshot(&mut a);
    let mut used = Vec::new();
    for t in ["t1", "t2"] {
        a.core.enqueue(&b.id(), t, 2).unwrap();
        let (wire, st) = send_one(&a, &b);
        assert_eq!(st, AckStatus::Stored);
        used.push(position(&wire));
    }
    a.restart();
    // Put back the session files only; the outbox and history stay.
    let chat = a.dir.path().join("chat");
    for e in fs::read_dir(snap.chat.path()).unwrap().flatten() {
        if crate::paths::is_chat_session_file(&e.path()) {
            fs::copy(e.path(), chat.join(e.file_name())).unwrap();
        }
    }
    a.restart();
    a.core.enqueue(&b.id(), "after", 3).unwrap();
    let (wire, st) = send_one(&a, &b);
    assert!(!used.contains(&position(&wire)));
    assert_eq!(st, AckStatus::Stored);
}

#[test]
fn a_record_older_than_the_data_starts_a_new_session() {
    // The record put back to an earlier state while the data stays current:
    // the file is "newer than the record", which is also not the file the
    // record names. The side starts a new session (the safe direction).
    let (mut a, b) = (side(), side());
    establish(&a, &b);
    let snap = snapshot(&mut a);
    a.core.enqueue(&b.id(), "one", 2).unwrap();
    assert_eq!(deliver_next(&a, &b), Some(AckStatus::Stored));
    a.core.store.close();
    fs::remove_dir_all(a.anchor.path()).unwrap();
    copy_tree(snap.anchor.path(), a.anchor.path());
    a.restart();
    a.core.enqueue(&b.id(), "two", 3).unwrap();
    let (_, st) = send_one(&a, &b);
    assert_eq!(st, AckStatus::Stored);
    assert_eq!(b.texts(&a.id()), ["hello", "hello back", "one", "two"]);
}

// ── What it cannot close: the record goes back or away with the data ─────────

#[test]
fn limit_a_full_restore_of_data_and_record_repeats_positions_and_the_receiver_recovers() {
    let (mut a, mut b) = (side(), side());
    let (used, _) = restore_across_ratchet_steps(&mut a, &mut b, true, Record::PutBack);
    let (peer_b, peer_a) = (b.id(), a.id());
    a.core.enqueue(&peer_b, "q1", 3).unwrap();
    let (wire, st) = send_one(&a, &b);
    // Documented limit: the old file looks like the latest one, so the first
    // message after the restore takes a position that was used before...
    assert_eq!(position(&wire), position(&used));
    // ...and is refused. The refusal makes the sender start a new session.
    assert_eq!(st, UNOPENABLE_ANSWER);
    a.core.reset_session(&peer_b);
    assert_eq!(send_one(&a, &b).1, AckStatus::Stored);
    assert_eq!(received(&b, &peer_a), ["hello", "q1"]);
}

#[test]
fn limit_without_a_record_the_data_is_trusted_and_the_record_is_made_again() {
    let (mut a, mut b) = (side(), side());
    let (used, _) = restore_across_ratchet_steps(&mut a, &mut b, true, Record::Removed);
    let (peer_b, _) = (b.id(), a.id());
    a.core.enqueue(&peer_b, "q1", 3).unwrap();
    let (wire, st) = send_one(&a, &b);
    assert_eq!(position(&wire), position(&used));
    assert_eq!(st, UNOPENABLE_ANSWER);
    // The record exists again, for the next time.
    assert!(fs::read_dir(a.anchor.path()).unwrap().count() > 0);
}

#[test]
fn a_missing_record_with_current_data_changes_nothing() {
    let (mut a, b) = (side(), side());
    establish(&a, &b);
    a.core.enqueue(&b.id(), "one", 2).unwrap();
    assert_eq!(deliver_next(&a, &b), Some(AckStatus::Stored));
    a.core.store.close();
    fs::remove_dir_all(a.anchor.path()).unwrap();
    fs::create_dir_all(a.anchor.path()).unwrap();
    a.restart();
    a.core.enqueue(&b.id(), "two", 3).unwrap();
    let (wire, st) = send_one(&a, &b);
    assert_eq!(st, AckStatus::Stored);
    // Still the same chain: the session was not dropped.
    assert!(Envelope::decode(&wire).unwrap().header.init_ek.is_none());
    assert!(fs::read_dir(a.anchor.path()).unwrap().count() > 0);
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
fn a_first_flight_message_of_a_known_key_gets_no_session_when_there_is_no_session() {
    let (a, b) = (side(), side());
    // Two messages before any reply: both carry the first-flight key.
    a.core.enqueue(&b.id(), "m1", 1).unwrap();
    a.core.enqueue(&b.id(), "m2", 1).unwrap();
    let e1 = a.core.outbox.first_for(&b.id()).unwrap();
    let (w1, _) = a.core.prepare_wire(&e1.id).unwrap();
    assert_eq!(b.core.accept(&a.id(), &w1, 2).status, AckStatus::Stored);
    a.core.mark_delivered(&e1.id, 3);
    let e2 = a.core.outbox.first_for(&b.id()).unwrap();
    let (w2, _) = a.core.prepare_wire(&e2.id).unwrap();
    assert!(Envelope::decode(&w2).unwrap().header.init_ek.is_some());
    // The receiver lost the session but remembers the key.
    b.core.reset_session(&a.id());
    assert_eq!(b.core.accept(&a.id(), &w2, 4).status, AckStatus::NoSession);
    assert_eq!(
        b.core.accept_raw(&a.id(), &w2, |_| AckStatus::Stored),
        AckStatus::NoSession
    );
}
