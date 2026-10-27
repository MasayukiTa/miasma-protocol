//! Tests of the chat engine without a network: two engines hand envelopes to
//! each other directly.

use std::sync::Arc;

use tempfile::TempDir;

use super::{
    anchor::Anchor,
    crypto::Identity,
    engine::{ChatCore, EnqueueError},
    outbox::Outbox,
    proto::AckStatus,
    store::{ChatStore, MsgState, StoreSettings},
};
use crate::state_crypto::StateKeys;

pub(super) struct Side {
    pub(super) dir: TempDir,
    pub(super) seed: [u8; 32],
    pub(super) master: [u8; 32],
    /// Where the record of the last session files written lives: not inside
    /// `dir`, as in a real installation.
    pub(super) anchor: TempDir,
    pub(super) core: ChatCore,
}

pub(super) fn open_core(
    dir: &std::path::Path,
    anchor: Option<&std::path::Path>,
    seed: &[u8; 32],
    master: &[u8; 32],
    s: StoreSettings,
    max: usize,
) -> ChatCore {
    let keys = Arc::new(StateKeys::from_master_key(master).unwrap());
    let id = Identity::from_seed(seed);
    let chat = dir.join("chat");
    let mut store = ChatStore::open(&chat, keys.clone(), id.id(), s.clone()).unwrap();
    if let Some(a) = anchor {
        store = store.with_anchor(Anchor::new(Some(a.to_path_buf()), keys.clone(), id.id()));
    }
    let (outbox, _) = Outbox::open(&crate::paths::chat_outbox_file(&chat), keys, s, 1);
    ChatCore::new(store, outbox, id, max)
}

pub(super) fn side_with(s: StoreSettings, max: usize) -> Side {
    let dir = tempfile::tempdir().unwrap();
    let seed: [u8; 32] = rand::random();
    let master: [u8; 32] = rand::random();
    let anchor = tempfile::tempdir().unwrap();
    let core = open_core(dir.path(), Some(anchor.path()), &seed, &master, s, max);
    Side {
        dir,
        seed,
        master,
        anchor,
        core,
    }
}

pub(super) fn side() -> Side {
    side_with(StoreSettings::default(), 4096)
}

impl Side {
    pub(super) fn id(&self) -> [u8; 32] {
        self.core.own_id()
    }

    pub(super) fn restart(&mut self) {
        self.core.store.close();
        self.core = open_core(
            self.dir.path(),
            Some(self.anchor.path()),
            &self.seed,
            &self.master,
            StoreSettings::default(),
            4096,
        );
    }

    pub(super) fn texts(&self, peer: &[u8; 32]) -> Vec<String> {
        self.core
            .history(peer, None, 200)
            .into_iter()
            .map(|m| m.text)
            .collect()
    }
}

/// Send one queued message of `from` to `to`; returns the status.
pub(super) fn deliver_next(from: &Side, to: &Side) -> Option<AckStatus> {
    let peer = to.id();
    let e = from.core.outbox.first_for(&peer)?;
    let (wire, _) = from.core.prepare_wire(&e.id).unwrap();
    let st = to.core.accept(&from.id(), &wire, 5).status;
    if st.is_delivered() {
        from.core.mark_delivered(&e.id, 6);
    }
    Some(st)
}

#[cfg(feature = "pqc")]
#[test]
fn call_dispatch_and_chat_receive() {
    use super::call::{
        inbound::dispatch,
        signal::{new_call_id, new_call_nonce, Record},
    };
    use super::engine::now_ms;

    let a = side();
    let b = side();
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let now = now_ms();
    let offer = |expires_at_ms| {
        Record::Offer {
            call_id: new_call_id(),
            call_nonce: new_call_nonce(),
            created_at_ms: now,
            expires_at_ms,
            capabilities: vec![1],
        }
        .encode()
        .unwrap()
    };
    let send = |body: &[u8], allowed: bool| {
        let (wire, _) = a.core.seal_for(&b.id(), body).unwrap();
        let result = b.core.accept_with_call(&a.id(), &wire, now, &|plain| {
            dispatch(&tx, a.id(), allowed, plain, now);
        });
        assert_eq!(result.status, AckStatus::Stored);
    };
    send(&offer(now + 60_000), true);
    let received = rx.try_recv().unwrap();
    assert!(received.peer == a.id());
    assert_eq!(received.received_at_ms, now);
    assert!(matches!(received.signal, Record::Offer { .. }));
    send(&offer(now + 60_000), false);
    send(&offer(now.saturating_sub(1)), true);
    send(&[0x30, 0xff], true);
    assert!(rx.try_recv().is_err());
    assert!(b.texts(&a.id()).is_empty());

    let (wire, _) = a.core.seal_for(&b.id(), &offer(now + 60_000)).unwrap();
    assert_eq!(b.core.accept(&a.id(), &wire, now).status, AckStatus::Stored);
    assert!(b.texts(&a.id()).is_empty());
    a.core.enqueue(&b.id(), "hello", now).unwrap();
    let e = a.core.outbox.first_for(&b.id()).unwrap();
    let (wire, _) = a.core.prepare_wire(&e.id).unwrap();
    assert_eq!(
        b.core
            .accept_with_call(&a.id(), &wire, now, &|plain| {
                dispatch(&tx, a.id(), true, plain, now);
            })
            .status,
        AckStatus::Stored
    );
    assert!(rx.try_recv().is_err());
    assert_eq!(b.texts(&a.id()), ["hello"]);
}

#[test]
fn messages_flow_both_ways_in_order_and_are_applied_once() {
    let a = side();
    let b = side();
    for t in ["one", "two", "three"] {
        a.core.enqueue(&b.id(), t, 1).unwrap();
    }
    for _ in 0..3 {
        assert_eq!(deliver_next(&a, &b), Some(AckStatus::Stored));
    }
    b.core.enqueue(&a.id(), "reply", 2).unwrap();
    assert_eq!(deliver_next(&b, &a), Some(AckStatus::Stored));
    a.core.enqueue(&b.id(), "four", 3).unwrap();
    assert_eq!(deliver_next(&a, &b), Some(AckStatus::Stored));
    let both = ["one", "two", "three", "reply", "four"];
    assert_eq!(b.texts(&a.id()), both);
    assert_eq!(a.texts(&b.id()), both);
    assert_eq!(a.core.outbox.len(), 0);
    let hist = a.core.history(&b.id(), None, 50);
    assert!(hist
        .iter()
        .filter(|m| m.outgoing)
        .all(|m| m.state == MsgState::Delivered));
}

#[test]
fn the_same_envelope_twice_is_stored_once() {
    let a = side();
    let b = side();
    let id = a.core.enqueue(&b.id(), "once", 1).unwrap();
    let (wire, _) = a.core.prepare_wire(&id).unwrap();
    assert_eq!(b.core.accept(&a.id(), &wire, 2).status, AckStatus::Stored);
    // The retry after a lost acknowledgement, in the same process and after a restart.
    assert_eq!(
        b.core.accept(&a.id(), &wire, 3).status,
        AckStatus::Duplicate
    );
    let mut b = b;
    b.restart();
    assert_eq!(
        b.core.accept(&a.id(), &wire, 4).status,
        AckStatus::Duplicate
    );
    assert_eq!(b.texts(&a.id()), ["once"]);
}

#[test]
fn a_resend_after_the_lost_acknowledgement_is_the_same_bytes_and_applied_once() {
    let a = side();
    let b = side();
    let id = a.core.enqueue(&b.id(), "same message", 1).unwrap();
    let (w1, _) = a.core.prepare_wire(&id).unwrap();
    assert_eq!(b.core.accept(&a.id(), &w1, 2).status, AckStatus::Stored);
    // The sender restarts before it saw the acknowledgement. The sealed
    // envelope was kept, so the very same bytes go out again.
    let mut a = a;
    a.restart();
    let (w2, _) = a.core.prepare_wire(&id).unwrap();
    assert_eq!(w1, w2);
    assert_eq!(b.core.accept(&a.id(), &w2, 3).status, AckStatus::Duplicate);
    assert_eq!(b.texts(&a.id()), ["same message"]);
}

#[test]
fn out_of_order_envelopes_are_all_applied() {
    let a = side();
    let b = side();
    let ids: Vec<_> = ["a", "b", "c", "d"]
        .iter()
        .map(|t| a.core.enqueue(&b.id(), t, 1).unwrap())
        .collect();
    let wires: Vec<_> = ids
        .iter()
        .map(|id| a.core.prepare_wire(id).unwrap().0)
        .collect();
    for i in [2usize, 0, 3, 1] {
        assert_eq!(
            b.core.accept(&a.id(), &wires[i], 5).status,
            AckStatus::Stored
        );
    }
    let mut got = b.texts(&a.id());
    got.sort();
    assert_eq!(got, ["a", "b", "c", "d"]);
}

#[test]
fn damaged_envelopes_are_rejected_and_nothing_is_stored() {
    let a = side();
    let b = side();
    let id = a.core.enqueue(&b.id(), "secret", 1).unwrap();
    let (wire, _) = a.core.prepare_wire(&id).unwrap();
    for i in 0..wire.len() {
        let mut bad = wire.clone();
        bad[i] ^= 0x40;
        let st = b.core.accept(&a.id(), &bad, 2).status;
        assert!(
            matches!(
                st,
                AckStatus::BadRequest | AckStatus::Unsupported | AckStatus::NoSession
            ),
            "byte {i}: {st:?}"
        );
    }
    assert!(b.texts(&a.id()).is_empty());
    // The genuine one still works afterwards.
    assert_eq!(b.core.accept(&a.id(), &wire, 3).status, AckStatus::Stored);
    // A third party cannot inject under another identity.
    let c = side();
    let id2 = c.core.enqueue(&b.id(), "forged", 1).unwrap();
    let (w3, _) = c.core.prepare_wire(&id2).unwrap();
    assert_eq!(b.core.accept(&a.id(), &w3, 4).status, AckStatus::BadRequest);
    assert_eq!(b.texts(&a.id()), ["secret"]);
}

#[test]
fn unknown_versions_get_a_polite_answer_and_junk_is_a_bad_request() {
    let a = side();
    let b = side();
    let id = a.core.enqueue(&b.id(), "x", 1).unwrap();
    let (mut wire, _) = a.core.prepare_wire(&id).unwrap();
    wire[0] = 9;
    assert_eq!(
        b.core.accept(&a.id(), &wire, 2).status,
        AckStatus::Unsupported
    );
    assert_eq!(
        b.core.accept(&a.id(), &[1u8, 2, 1, 0], 2).status,
        AckStatus::BadRequest
    );
    assert_eq!(b.core.accept(&a.id(), b"", 2).status, AckStatus::BadRequest);
}

#[test]
fn too_large_messages_are_refused_on_both_sides() {
    let a = side();
    assert_eq!(
        a.core.enqueue(&[7u8; 32], &"x".repeat(4097), 1),
        Err(EnqueueError::TooBig)
    );
    assert_eq!(a.core.enqueue(&[7u8; 32], "", 1), Err(EnqueueError::Empty));
    // A receiver with a smaller limit than the sender.
    let b = side_with(StoreSettings::default(), 10);
    let id = a
        .core
        .enqueue(&b.id(), "this is longer than ten bytes", 1)
        .unwrap();
    let (wire, _) = a.core.prepare_wire(&id).unwrap();
    assert_eq!(b.core.accept(&a.id(), &wire, 2).status, AckStatus::TooBig);
    assert!(b.texts(&a.id()).is_empty());
}

#[test]
fn the_outbox_is_bounded() {
    let s = StoreSettings {
        outbox_max: 3,
        ..StoreSettings::default()
    };
    let a = side_with(s, 4096);
    let peer = [8u8; 32];
    for i in 0..3 {
        a.core.enqueue(&peer, &format!("m{i}"), 1).unwrap();
    }
    assert_eq!(
        a.core.enqueue(&peer, "m3", 1),
        Err(EnqueueError::OutboxFull)
    );
    // Per-contact bound and byte bound.
    let s = StoreSettings {
        outbox_max_per_contact: 2,
        ..StoreSettings::default()
    };
    let a = side_with(s, 4096);
    a.core.enqueue(&peer, "1", 1).unwrap();
    a.core.enqueue(&peer, "2", 1).unwrap();
    assert_eq!(a.core.enqueue(&peer, "3", 1), Err(EnqueueError::OutboxFull));
    a.core.enqueue(&[9u8; 32], "other contact", 1).unwrap();
}

#[test]
fn queued_messages_survive_a_restart_and_are_delivered_in_order() {
    let mut a = side();
    let b = side();
    for t in ["first", "second", "third"] {
        a.core.enqueue(&b.id(), t, 1).unwrap();
    }
    // One of them was sealed (and maybe sent) before the restart.
    let e = a.core.outbox.first_for(&b.id()).unwrap();
    let (lost, _) = a.core.prepare_wire(&e.id).unwrap();
    a.restart();
    assert_eq!(a.core.outbox.len(), 3);
    for _ in 0..3 {
        assert_eq!(deliver_next(&a, &b), Some(AckStatus::Stored));
    }
    assert_eq!(b.texts(&a.id()), ["first", "second", "third"]);
    // The envelope sealed before the restart still opens (once) and is only a duplicate.
    assert_eq!(
        b.core.accept(&a.id(), &lost, 9).status,
        AckStatus::Duplicate
    );
    assert_eq!(b.texts(&a.id()).len(), 3);
}

#[test]
fn a_peer_that_lost_its_session_is_brought_back() {
    let a = side();
    let mut b = side();
    a.core.enqueue(&b.id(), "hello", 1).unwrap();
    assert_eq!(deliver_next(&a, &b), Some(AckStatus::Stored));
    b.core.enqueue(&a.id(), "hi back", 1).unwrap();
    assert_eq!(deliver_next(&b, &a), Some(AckStatus::Stored));
    // B loses its session state (its sessions are deleted).
    b.core.store.close();
    for e in std::fs::read_dir(b.dir.path().join("chat"))
        .unwrap()
        .flatten()
    {
        if crate::paths::is_chat_session_file(&e.path()) {
            std::fs::remove_file(e.path()).unwrap();
        }
    }
    b.restart();
    a.core.enqueue(&b.id(), "are you there", 2).unwrap();
    let st = deliver_next(&a, &b);
    assert_eq!(st, Some(AckStatus::NoSession));
    a.core.reset_session(&b.id());
    assert_eq!(deliver_next(&a, &b), Some(AckStatus::Stored));
    assert_eq!(
        b.texts(&a.id()).last().map(String::as_str),
        Some("are you there")
    );
}

#[test]
fn both_sides_starting_at_once_still_deliver_everything() {
    let a = side();
    let b = side();
    a.core.enqueue(&b.id(), "from a", 1).unwrap();
    b.core.enqueue(&a.id(), "from b", 1).unwrap();
    for _ in 0..8 {
        for (x, y) in [(&a, &b), (&b, &a)] {
            if deliver_next(x, y) == Some(AckStatus::NoSession) {
                x.core.reset_session(&y.id());
            }
        }
    }
    assert_eq!(a.core.outbox.len() + b.core.outbox.len(), 0);
    assert!(a.texts(&b.id()).contains(&"from b".to_string()));
    assert!(b.texts(&a.id()).contains(&"from a".to_string()));
}

#[test]
fn history_survives_a_restart_and_is_encrypted_at_rest() {
    let mut a = side();
    let b = side();
    let marker = "MARKER-ZZ-7f3a91-縺薙ｓ縺ｫ縺｡縺ｯ";
    a.core.enqueue(&b.id(), marker, 1).unwrap();
    assert_eq!(deliver_next(&a, &b), Some(AckStatus::Stored));
    let mut b = b;
    b.core.enqueue(&a.id(), marker, 1).unwrap();
    assert_eq!(deliver_next(&b, &a), Some(AckStatus::Stored));
    a.restart();
    b.restart();
    assert_eq!(a.texts(&b.id()), [marker, marker]);
    assert_eq!(b.texts(&a.id()), [marker, marker]);
    for s in [&a, &b] {
        s.core.store.close();
        for e in walk(s.dir.path()) {
            let bytes = std::fs::read(&e).unwrap();
            assert!(
                !contains(&bytes, marker.as_bytes()) && !contains(&bytes, b"MARKER-ZZ"),
                "plaintext in {e:?}"
            );
        }
    }
}

fn walk(p: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(p).unwrap().flatten() {
        let path = e.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn ephemeral_mode_never_writes_a_message_to_disk() {
    let s = StoreSettings {
        history_save: false,
        ..StoreSettings::default()
    };
    let a = side_with(s.clone(), 4096);
    let b = side_with(s, 4096);
    let marker = "EPHEMERAL-MARKER-91c2";
    a.core.enqueue(&b.id(), marker, 1).unwrap();
    assert_eq!(deliver_next(&a, &b), Some(AckStatus::Stored));
    assert_eq!(b.texts(&a.id()), [marker]);
    assert_eq!(a.texts(&b.id()), [marker]);
    for s in [&a, &b] {
        s.core.store.close();
        for f in walk(s.dir.path()) {
            let name = f.file_name().unwrap().to_string_lossy().into_owned();
            assert!(!name.ends_with(".msgs"), "{name}");
            assert!(!contains(&std::fs::read(&f).unwrap(), b"EPHEMERAL"));
        }
    }
}

#[test]
fn delete_removes_a_message_or_a_conversation_and_cancels_queued_ones() {
    let a = side();
    let b = side();
    for t in ["keep", "drop", "queued"] {
        a.core.enqueue(&b.id(), t, 1).unwrap();
    }
    deliver_next(&a, &b);
    deliver_next(&a, &b);
    let hist = a.core.history(&b.id(), None, 50);
    let drop_id = hist.iter().find(|m| m.text == "drop").unwrap().id;
    assert!(a.core.delete_message(&b.id(), &drop_id).unwrap());
    let queued_id = hist.iter().find(|m| m.text == "queued").unwrap().id;
    assert!(a.core.delete_message(&b.id(), &queued_id).unwrap());
    assert_eq!(a.texts(&b.id()), ["keep"]);
    assert_eq!(a.core.outbox.len(), 0);
    a.core.delete_conversation(&b.id()).unwrap();
    assert!(a.texts(&b.id()).is_empty());
    // The pair still works afterwards (counters were kept).
    a.core.enqueue(&b.id(), "after", 5).unwrap();
    assert_eq!(deliver_next(&a, &b), Some(AckStatus::Stored));
    assert_eq!(b.texts(&a.id()), ["keep", "drop", "after"]);
}

#[test]
fn events_report_arrivals_and_results() {
    let a = side();
    let b = side();
    a.core.enqueue(&b.id(), "ping", 1).unwrap();
    deliver_next(&a, &b);
    let (next, ev) = b.core.events_since(0);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].message.text, "ping");
    let (_, again) = b.core.events_since(next);
    assert!(again.is_empty());
    let (_, ev) = a.core.events_since(0);
    assert_eq!(ev.len(), 1);
}

// ─── Skew with other releases ────────────────────────────────────────────────

#[test]
fn a_record_kind_from_a_newer_build_is_acknowledged_and_the_session_goes_on() {
    let a = side();
    let b = side();
    a.core.enqueue(&b.id(), "first", 1).unwrap();
    assert_eq!(deliver_next(&a, &b), Some(AckStatus::Stored));
    // A kind this build does not know, sealed in a real envelope.
    let (wire, _) = a.core.seal_for(&b.id(), &[77, 1, 2, 3, 4]).unwrap();
    assert_eq!(b.core.accept(&a.id(), &wire, 3).status, AckStatus::Stored);
    // The same bytes again are a duplicate, and later messages still arrive.
    assert_eq!(
        b.core.accept(&a.id(), &wire, 4).status,
        AckStatus::Duplicate
    );
    a.core.enqueue(&b.id(), "second", 5).unwrap();
    assert_eq!(deliver_next(&a, &b), Some(AckStatus::Stored));
    assert_eq!(b.texts(&a.id()), ["first", "second"]);
}

#[test]
fn a_text_record_with_fields_appended_by_a_newer_build_is_read() {
    let a = side();
    let b = side();
    let mut plain = super::proto::Message {
        id: rand::random(),
        seq: 1,
        sent_ms: 1_700_000_000_000,
        text: "hello".into(),
    }
    .encode()
    .unwrap();
    plain.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
    let (wire, _) = a.core.seal_for(&b.id(), &plain).unwrap();
    assert_eq!(b.core.accept(&a.id(), &wire, 2).status, AckStatus::Stored);
    assert_eq!(b.texts(&a.id()), ["hello"]);
}
