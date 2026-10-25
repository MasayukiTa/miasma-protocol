//! Tests of the hybrid upgrade of private-conversation sessions (feature
//! `pqc`): two engines hand envelopes to each other directly, driven by the
//! same decisions the delivery worker takes (`ChatCore::pq_step`).
//!
//! All key material is drawn at run time; nothing here is a literal key.

use super::{
    crypto::Envelope,
    engine_tests::{deliver_next, side, Side},
    pq::{
        self, counts, Pass, PqcRefusal, SendOutcome, FAIL_EXCHANGE, FAIL_NO_HYBRID, KIND_CONFIRM,
        KIND_INIT, KIND_OFFER, KIND_RESP, OFFER_WAIT_MS,
    },
    store::MsgState,
};
use crate::{config::PqcMode, protocol::capability::Capabilities};

fn mode(s: &Side, m: PqcMode) {
    s.core.set_pqc_mode(m);
}

/// How a test peer treats a record it receives.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Peer {
    /// Opens everything this build sends.
    Current,
    /// A build from before the hybrid upgrade that answers "bad request" for a
    /// record kind it does not know (and does not move its session).
    Strict,
}

type Hook<'a> = &'a dyn Fn(u8, &mut Vec<u8>);

/// One step of the delivery loop of `from` towards `to`. True when something
/// was done.
fn step(from: &Side, to: &Side, to_is: Peer, now: u64, hook: Option<Hook<'_>>) -> bool {
    let peer = to.id();
    let have_text = from.core.outbox.first_for(&peer).is_some();
    match from.core.pq_step(&peer, have_text, now) {
        Pass::Send(out) => {
            // The hook alters what goes on the wire; the sender still reports
            // the record it meant to send.
            let mut plain = out.plain.clone();
            if let Some(h) = hook {
                let kind = plain[0];
                h(kind, &mut plain);
            }
            let (wire, _) = from.core.seal_for(&peer, &plain).unwrap();
            let outcome = if to_is == Peer::Strict {
                SendOutcome::NotUnderstood
            } else {
                let st = to.core.accept(&from.id(), &wire, now).status;
                assert!(st.is_delivered(), "record answered {st:?}");
                SendOutcome::Delivered
            };
            from.core.pq_sent(&peer, &out, outcome, now);
            true
        }
        Pass::Refuse(refusal) => {
            if let Some(e) = from.core.outbox.first_for(&peer) {
                from.core.mark_failed(&e.id, refusal.reason_str(), now);
            }
            true
        }
        Pass::Hold => false,
        Pass::Proceed => deliver_next(from, to).is_some(),
    }
}

fn pump_with(a: &Side, b: &Side, b_is: Peer, now: u64, hook: Option<Hook<'_>>) {
    for _ in 0..400 {
        let x = step(a, b, b_is, now, hook);
        let y = step(b, a, Peer::Current, now, hook);
        if !x && !y {
            return;
        }
    }
    panic!("the exchange does not settle");
}

fn pump(a: &Side, b: &Side, now: u64) {
    pump_with(a, b, Peer::Current, now, None);
}

fn state_of(s: &Side, peer: &Side) -> (&'static str, Option<&'static str>) {
    let v = s.core.pq_view(&peer.id());
    (v.state, v.reason)
}

/// The side that starts the exchange (smaller endpoint ID) and the other.
fn roles<'a>(a: &'a Side, b: &'a Side) -> (&'a Side, &'a Side) {
    if a.id() < b.id() {
        (a, b)
    } else {
        (b, a)
    }
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

fn pq_files(s: &Side) -> usize {
    std::fs::read_dir(s.dir.path().join("chat"))
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "pq"))
                .count()
        })
        .unwrap_or(0)
}

// ─── Both sides hybrid ──────────────────────────────────────────────────────

#[test]
fn hybrid_to_hybrid_session_works_and_messages_round_trip() {
    let before = counts();
    let a = side();
    let b = side();
    mode(&a, PqcMode::Prefer);
    mode(&b, PqcMode::Prefer);
    a.core.enqueue(&b.id(), "one", 1).unwrap();
    pump(&a, &b, 1_000);
    b.core.enqueue(&a.id(), "two", 2).unwrap();
    a.core.enqueue(&b.id(), "three", 3).unwrap();
    pump(&a, &b, 2_000);
    // Both sides hold all three (the order of the two directions can differ).
    assert_eq!(sorted(b.texts(&a.id())), ["one", "three", "two"]);
    assert_eq!(sorted(a.texts(&b.id())), ["one", "three", "two"]);
    assert_eq!(state_of(&a, &b), ("hybrid", None));
    assert_eq!(state_of(&b, &a), ("hybrid", None));
    assert!(counts().hybrid_sessions >= before.hybrid_sessions + 2);

    // From here on a message is protected by the hybrid key as well: the plain
    // ratchet cannot open it, the ratchet plus the hybrid key can.
    let id = a.core.enqueue(&b.id(), "layered", 4).unwrap();
    let (wire, _) = a.core.prepare_wire(&id).unwrap();
    let env = Envelope::decode(&wire).unwrap();
    let (mut plain_only, mut with_key, key) = {
        let sid = b
            .core
            .store
            .peek_peer(&a.id(), |st| *st.session.as_ref().unwrap().origin_ek());
        let k = b.core.pq.open_key(&a.id(), &sid).expect("key");
        let s = b
            .core
            .store
            .peek_peer(&a.id(), |st| st.session.clone().unwrap());
        (s.clone(), s, k)
    };
    assert!(plain_only.open(&env).is_err());
    let opened = with_key.open_with(&env, Some(&key)).unwrap();
    assert!(!opened.is_empty());
    // And the engine delivers it.
    assert!(b.core.accept(&a.id(), &wire, 5).status.is_delivered());
    assert_eq!(b.texts(&a.id()).last().unwrap(), "layered");
}

#[test]
fn classical_to_classical_is_unchanged_and_writes_nothing_extra() {
    let a = side();
    let b = side();
    // Default mode: off.
    a.core.enqueue(&b.id(), "x", 1).unwrap();
    b.core.enqueue(&a.id(), "y", 2).unwrap();
    pump(&a, &b, 1_000);
    assert_eq!(b.texts(&a.id()), ["x", "y"]);
    assert_eq!(pq_files(&a), 0);
    assert_eq!(pq_files(&b), 0);
    assert_eq!(state_of(&a, &b).0, "off");
    // No hybrid key exists, so every message is a plain ratchet message.
    let sid = a
        .core
        .store
        .peek_peer(&b.id(), |st| *st.session.as_ref().unwrap().origin_ek());
    assert!(a.core.pq.seal_key(&b.id(), &sid).is_none());
    assert!(a.core.pq.open_key(&b.id(), &sid).is_none());
}

// ─── Downgrades are visible, nothing breaks ─────────────────────────────────

#[test]
fn prefer_with_a_classical_peer_downgrades_visibly_and_messages_flow() {
    let before = counts();
    let missing = crate::protocol::capability::downgrade_counts().offer_missing;
    let a = side();
    let b = side();
    mode(&a, PqcMode::Prefer);
    // `b` stays off: it offers nothing and answers nothing.
    a.core.enqueue(&b.id(), "hello", 1).unwrap();
    pump(&a, &b, 1_000);
    assert_eq!(b.texts(&a.id()), ["hello"]);
    assert_eq!(state_of(&a, &b).0, "pending");
    // The wait for an offer is over: classical only, with the reason.
    a.core.enqueue(&b.id(), "again", 2).unwrap();
    pump(&a, &b, 1_000 + OFFER_WAIT_MS + 1);
    assert_eq!(state_of(&a, &b), ("classical", Some("peer_no_hybrid")));
    assert_eq!(b.texts(&a.id()), ["hello", "again"]);
    let after = counts();
    assert!(after.classical_only >= before.classical_only + 1);
    // Not a refusal: that is only for `require`.
    assert!(
        crate::protocol::capability::downgrade_counts().offer_missing >= missing + 1,
        "the missing offer is counted by the capability counters"
    );
    // The other side replies in the same classical session.
    b.core.enqueue(&a.id(), "reply", 3).unwrap();
    pump(&a, &b, 1_000 + OFFER_WAIT_MS + 2);
    assert_eq!(a.texts(&b.id()).last().unwrap(), "reply");
}

#[test]
fn the_wait_for_an_offer_has_a_deadline_the_delivery_loop_can_wait_for() {
    let a = side();
    let b = side();
    mode(&a, PqcMode::Prefer);
    a.core.enqueue(&b.id(), "hello", 1).unwrap();
    assert_eq!(
        a.core.pq_deadline(&b.id(), 1_000),
        None,
        "nothing offered yet"
    );
    pump(&a, &b, 1_000);
    assert_eq!(a.core.pq_deadline(&b.id(), 1_000), Some(OFFER_WAIT_MS));
    assert_eq!(
        a.core.pq_deadline(&b.id(), 1_000 + OFFER_WAIT_MS - 5),
        Some(5)
    );
    // Once the wait is over the decision is taken and nothing is pending.
    let _ = a.core.pq_step(&b.id(), false, 1_000 + OFFER_WAIT_MS);
    assert_eq!(a.core.pq_deadline(&b.id(), 1_000 + OFFER_WAIT_MS), None);
    assert_eq!(state_of(&a, &b).0, "classical");
}

#[test]
fn prefer_with_a_build_that_rejects_the_offer_downgrades_at_once() {
    let a = side();
    let b = side();
    mode(&a, PqcMode::Prefer);
    a.core.enqueue(&b.id(), "hi", 1).unwrap();
    pump_with(&a, &b, Peer::Strict, 1_000, None);
    // The text still arrived: the offer left the session as it was.
    assert_eq!(b.texts(&a.id()), ["hi"]);
    assert_eq!(state_of(&a, &b), ("classical", Some("peer_old_build")));
    // The reply opens too.
    b.core.enqueue(&a.id(), "yo", 2).unwrap();
    pump_with(&a, &b, Peer::Strict, 1_001, None);
    assert_eq!(a.texts(&b.id()).last().unwrap(), "yo");
}

#[test]
fn require_with_a_classical_peer_fails_locally_with_the_reason() {
    let before = counts();
    let a = side();
    let b = side();
    mode(&a, PqcMode::Require);
    a.core.enqueue(&b.id(), "secret", 1).unwrap();
    pump(&a, &b, 1_000);
    // Held: nothing was sent in the classical session.
    assert!(b.texts(&a.id()).is_empty());
    assert_eq!(a.core.outbox.len(), 1);
    pump(&a, &b, 1_000 + OFFER_WAIT_MS + 1);
    assert!(b.texts(&a.id()).is_empty(), "no classical fallback");
    assert_eq!(a.core.outbox.len(), 0);
    let hist = a.core.history(&b.id(), None, 10);
    assert_eq!(hist.len(), 1);
    assert_eq!(hist[0].state, MsgState::Failed);
    assert_eq!(hist[0].reason.as_deref(), Some(FAIL_NO_HYBRID));
    assert!(counts().refused >= before.refused + 1);
    // A message queued later fails the same way; it is never sent.
    a.core.enqueue(&b.id(), "later", 2).unwrap();
    pump(&a, &b, 1_000 + OFFER_WAIT_MS + 2);
    assert!(b.texts(&a.id()).is_empty());
    // The other side is unaffected: it sends, and `a` receives.
    b.core.enqueue(&a.id(), "from b", 3).unwrap();
    pump(&a, &b, 1_000 + OFFER_WAIT_MS + 3);
    assert_eq!(a.texts(&b.id()).last().unwrap(), "from b");
}

#[test]
fn require_with_a_build_that_rejects_the_offer_fails_at_once() {
    let a = side();
    let b = side();
    mode(&a, PqcMode::Require);
    a.core.enqueue(&b.id(), "secret", 1).unwrap();
    pump_with(&a, &b, Peer::Strict, 1_000, None);
    assert!(b.texts(&a.id()).is_empty());
    let hist = a.core.history(&b.id(), None, 10);
    assert_eq!(hist[0].reason.as_deref(), Some(FAIL_NO_HYBRID));
}

#[test]
fn require_with_a_tampered_mlkem_part_fails_and_never_falls_to_classical() {
    // `require` side talks to a peer that offers the suite, but the ML-KEM
    // response is corrupted on the wire. The exchange must fail (no key
    // confirmation) and nothing may be sent in a classical session.
    let a = side();
    let b = side();
    mode(&a, PqcMode::Require);
    mode(&b, PqcMode::Prefer);
    let (init, resp) = roles(&a, &b);
    // Flip the last byte of the responder's ML-KEM fragment (the ciphertext).
    let hook = |kind: u8, plain: &mut Vec<u8>| {
        if kind == KIND_RESP {
            let n = plain.len();
            plain[n - 1] ^= 0x01;
        }
    };
    // The `require` side is the one that must not fall back. Queue its message.
    let (req_side, other) = if init.core.pqc_mode() == PqcMode::Require {
        (init, resp)
    } else {
        (resp, init)
    };
    req_side.core.enqueue(&other.id(), "secret", 1).unwrap();
    pump_with(init, resp, Peer::Current, 1_000, Some(&hook));
    // Failed on the require side, and nothing reached the peer in the clear.
    assert_eq!(state_of(req_side, other).0, "failed");
    assert!(
        other.texts(&req_side.id()).is_empty(),
        "no classical fallback under require"
    );
    let hist = req_side.core.history(&other.id(), None, 10);
    assert_eq!(hist[0].state, MsgState::Failed);
    // No hybrid key was installed either.
    let sid = req_side
        .core
        .store
        .peek_peer(&other.id(), |st| *st.session.as_ref().unwrap().origin_ek());
    assert!(req_side.core.pq.seal_key(&other.id(), &sid).is_none());
    assert!(req_side.core.pq.open_key(&other.id(), &sid).is_none());
}

#[test]
fn require_with_a_forged_offer_fails_and_never_falls_to_classical() {
    // The responder's offer reaches the `require` initiator altered (a capability
    // declaration that does not match what is actually sent). The transcript
    // binding catches it; under `require` the message is not sent classically.
    let a = side();
    let b = side();
    mode(&a, PqcMode::Require);
    mode(&b, PqcMode::Prefer);
    let (init, resp) = roles(&a, &b);
    let altered = Capabilities::current()
        .with_unknown(vec![1, 2, 3])
        .unwrap()
        .encode();
    let alter = std::cell::Cell::new(false);
    let hook = |kind: u8, plain: &mut Vec<u8>| {
        if kind == KIND_OFFER && alter.get() {
            plain.truncate(1);
            plain.extend_from_slice(&altered);
            alter.set(false);
        }
    };
    init.core.enqueue(&resp.id(), "secret", 1).unwrap();
    assert!(step(init, resp, Peer::Current, 1_000, Some(&hook)));
    alter.set(true);
    assert!(step(resp, init, Peer::Current, 1_000, Some(&hook)));
    pump_with(init, resp, Peer::Current, 1_000, Some(&hook));
    let (req_side, other) = if init.core.pqc_mode() == PqcMode::Require {
        (init, resp)
    } else {
        (resp, init)
    };
    assert_eq!(state_of(req_side, other).0, "failed");
    assert!(
        other.texts(&req_side.id()).is_empty(),
        "no classical fallback under require"
    );
    let sid = req_side
        .core
        .store
        .peek_peer(&other.id(), |st| *st.session.as_ref().unwrap().origin_ek());
    assert!(req_side.core.pq.seal_key(&other.id(), &sid).is_none());
}

#[test]
fn require_sends_only_after_the_exchange_finished() {
    let a = side();
    let b = side();
    mode(&a, PqcMode::Require);
    mode(&b, PqcMode::Prefer);
    a.core.enqueue(&b.id(), "protected", 1).unwrap();
    // One step: the offer goes out, the text does not.
    assert!(step(&a, &b, Peer::Current, 1_000, None));
    assert!(b.texts(&a.id()).is_empty());
    pump(&a, &b, 1_000);
    assert_eq!(b.texts(&a.id()), ["protected"]);
    assert_eq!(state_of(&a, &b), ("hybrid", None));
}

#[test]
fn off_mode_ignores_offers_and_stays_silent() {
    let a = side();
    let b = side();
    mode(&b, PqcMode::Prefer);
    // `a` is off (the default) and receives b's offer and exchange attempts.
    b.core.enqueue(&a.id(), "from b", 1).unwrap();
    pump(&a, &b, 1_000);
    assert_eq!(a.texts(&b.id()), ["from b"]);
    assert_eq!(pq_files(&a), 0);
    assert_eq!(a.core.pq.in_memory(), 0, "an off build keeps no state");
    let sid = b
        .core
        .store
        .peek_peer(&a.id(), |st| *st.session.as_ref().unwrap().origin_ek());
    assert!(b.core.pq.open_key(&a.id(), &sid).is_none());
}

// ─── Altered messages are detected ──────────────────────────────────────────

#[test]
fn a_tampered_ciphertext_fails_the_exchange_and_is_shown() {
    let before = counts();
    let a = side();
    let b = side();
    mode(&a, PqcMode::Prefer);
    mode(&b, PqcMode::Prefer);
    // Flip the last byte of the responder's last fragment (the ciphertext tail).
    let (init, resp) = roles(&a, &b);
    let hook = |kind: u8, plain: &mut Vec<u8>| {
        if kind == KIND_RESP {
            let n = plain.len();
            plain[n - 1] ^= 0x01;
        }
    };
    init.core.enqueue(&resp.id(), "after", 1).unwrap();
    pump_with(init, resp, Peer::Current, 1_000, Some(&hook));
    // Messages still flow in the classical session; the failure is visible.
    assert_eq!(resp.texts(&init.id()), ["after"]);
    assert_eq!(state_of(init, resp).0, "failed");
    assert_eq!(state_of(resp, init).0, "failed");
    assert!(counts().failed >= before.failed + 2);
    // And it carried no hybrid key into the session.
    let sid = init
        .core
        .store
        .peek_peer(&resp.id(), |st| *st.session.as_ref().unwrap().origin_ek());
    assert!(init.core.pq.seal_key(&resp.id(), &sid).is_none());
    assert!(init.core.pq.open_key(&resp.id(), &sid).is_none());
    // Replies still open.
    resp.core.enqueue(&init.id(), "back", 2).unwrap();
    pump_with(init, resp, Peer::Current, 1_001, Some(&hook));
    assert_eq!(init.texts(&resp.id()).last().unwrap(), "back");
}

#[test]
fn an_altered_offer_is_caught_by_the_transcript_binding() {
    let a = side();
    let b = side();
    mode(&a, PqcMode::Prefer);
    mode(&b, PqcMode::Prefer);
    let (init, resp) = roles(&a, &b);
    // The responder's offer reaches the initiator with an extension block
    // that the responder never wrote.
    let altered = Capabilities::current()
        .with_unknown(vec![1, 2, 3])
        .unwrap()
        .encode();
    let alter = std::cell::Cell::new(false);
    let hook = |kind: u8, plain: &mut Vec<u8>| {
        if kind == KIND_OFFER && alter.get() {
            plain.truncate(1);
            plain.extend_from_slice(&altered);
            alter.set(false);
        }
    };
    // Let the initiator's offer through first, then alter the responder's.
    init.core.enqueue(&resp.id(), "x", 1).unwrap();
    assert!(step(init, resp, Peer::Current, 1_000, Some(&hook)));
    alter.set(true);
    assert!(step(resp, init, Peer::Current, 1_000, Some(&hook)));
    pump_with(init, resp, Peer::Current, 1_000, Some(&hook));
    assert_eq!(state_of(init, resp).0, "failed");
    assert_eq!(state_of(resp, init).0, "failed");
    assert_eq!(
        resp.texts(&init.id()),
        ["x"],
        "the session itself still works"
    );
}

#[test]
fn a_stripped_offer_means_classical_only_never_a_silent_hybrid() {
    let a = side();
    let b = side();
    mode(&a, PqcMode::Prefer);
    mode(&b, PqcMode::Prefer);
    // The offer of `b` never reaches `a` (removed on the way).
    let (init, resp) = roles(&a, &b);
    init.core.enqueue(&resp.id(), "m", 1).unwrap();
    assert!(step(init, resp, Peer::Current, 1_000, None));
    // Everything the responder would send is dropped before the initiator.
    let mut now = 1_000;
    for _ in 0..50 {
        let _ = step(resp, init, Peer::Strict, now, None);
        let _ = step(init, resp, Peer::Current, now, None);
        now += 1;
    }
    now += OFFER_WAIT_MS;
    pump_with(init, resp, Peer::Strict, now, None);
    assert_eq!(state_of(init, resp).0, "classical");
    let sid = init
        .core
        .store
        .peek_peer(&resp.id(), |st| *st.session.as_ref().unwrap().origin_ek());
    assert!(init.core.pq.seal_key(&resp.id(), &sid).is_none());
}

// ─── State is kept, bounded and wiped ───────────────────────────────────────

#[test]
fn the_hybrid_state_survives_a_restart() {
    let a = side();
    let mut b = side();
    mode(&a, PqcMode::Prefer);
    mode(&b, PqcMode::Prefer);
    a.core.enqueue(&b.id(), "one", 1).unwrap();
    pump(&a, &b, 1_000);
    assert_eq!(state_of(&b, &a).0, "hybrid");
    assert_eq!(pq_files(&b), 1);
    b.restart();
    mode(&b, PqcMode::Prefer);
    assert_eq!(state_of(&b, &a).0, "hybrid");
    a.core.enqueue(&b.id(), "two", 2).unwrap();
    b.core.enqueue(&a.id(), "three", 3).unwrap();
    pump(&a, &b, 2_000);
    assert_eq!(sorted(b.texts(&a.id())), ["one", "three", "two"]);
    assert_eq!(sorted(a.texts(&b.id())), ["one", "three", "two"]);
}

#[test]
fn a_reset_session_drops_its_hybrid_key() {
    let a = side();
    let b = side();
    mode(&a, PqcMode::Prefer);
    mode(&b, PqcMode::Prefer);
    a.core.enqueue(&b.id(), "one", 1).unwrap();
    pump(&a, &b, 1_000);
    assert_eq!(state_of(&a, &b).0, "hybrid");
    a.core.reset_session(&b.id());
    assert_eq!(pq_files(&a), 0);
    assert_eq!(a.core.pq.in_memory(), 0);
}

#[test]
fn wipe_zeroizes_the_session_secrets_and_removes_the_documents() {
    let a = side();
    let b = side();
    mode(&a, PqcMode::Prefer);
    mode(&b, PqcMode::Prefer);
    a.core.enqueue(&b.id(), "one", 1).unwrap();
    pump(&a, &b, 1_000);
    assert_eq!(pq_files(&a), 1);
    let drops = pq::key_drops();
    a.core.pq.wipe();
    // The key was dropped (and the drop asserts every byte was zero).
    assert!(pq::key_drops() > drops);
    assert_eq!(pq_files(&a), 0);
    assert_eq!(a.core.pq.in_memory(), 0);
    let sid = a
        .core
        .store
        .peek_peer(&b.id(), |st| *st.session.as_ref().unwrap().origin_ek());
    assert!(a.core.pq.seal_key(&a.id(), &sid).is_none());
    assert!(a.core.pq.seal_key(&b.id(), &sid).is_none());
}

#[test]
fn memory_for_unfinished_fragments_is_bounded() {
    use crate::protocol::hybrid::{MessageReassembler, SUITE_ID_HYBRID};
    let mut r = MessageReassembler::new();
    let msg = vec![7u8; 1_222];
    let mut refused = 0usize;
    // Thousands of handshakes that each send only their first fragment.
    for id in 0..5_000u64 {
        let frames = crate::protocol::hybrid::fragment_message(
            id,
            SUITE_ID_HYBRID,
            &msg,
            pq::FRAGMENT_PAYLOAD,
        )
        .unwrap();
        match r.push_frame(&frames[0], 1_000) {
            Ok(_) => {}
            Err(_) => refused += 1,
        }
        assert!(r.in_progress() <= 8, "{} in progress", r.in_progress());
    }
    assert!(refused > 4_000);
    // A fragment that declares a huge message is refused before any buffer.
    let mut frame =
        crate::protocol::hybrid::fragment_message(9, SUITE_ID_HYBRID, &msg, pq::FRAGMENT_PAYLOAD)
            .unwrap()
            .remove(0);
    // total_len sits at bytes 15..19 of the frame header.
    frame[15..19].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(MessageReassembler::new().push_frame(&frame, 2_000).is_err());
    // Every record of the exchange fits the smallest padding bucket.
    let frames = crate::protocol::hybrid::fragment_message(
        1,
        SUITE_ID_HYBRID,
        &vec![0u8; crate::protocol::hybrid::MAX_MESSAGE_LEN],
        pq::FRAGMENT_PAYLOAD,
    )
    .unwrap();
    assert!(frames.iter().all(|f| 1 + f.len() < 512));
}

#[test]
fn contacts_kept_in_memory_are_bounded() {
    let a = side();
    mode(&a, PqcMode::Prefer);
    for _ in 0..(pq::MAX_PEERS * 2) {
        let peer: [u8; 32] = rand::random();
        let sid: [u8; 32] = rand::random();
        let _ = a.core.pq.open_key(&peer, &sid);
        let _ = a.core.pq.on_record(&peer, &sid, &[KIND_OFFER, 1, 2], 1);
    }
    assert!(a.core.pq.in_memory() <= pq::MAX_PEERS);
}

#[test]
fn records_of_the_exchange_are_not_valid_for_the_wrong_role() {
    // An exchange message sent to the side that must not receive it changes
    // nothing and is acknowledged like any record.
    let a = side();
    let b = side();
    mode(&a, PqcMode::Prefer);
    mode(&b, PqcMode::Prefer);
    let (init, resp) = roles(&a, &b);
    init.core.enqueue(&resp.id(), "x", 1).unwrap();
    pump(init, resp, 1_000);
    let sid = init
        .core
        .store
        .peek_peer(&resp.id(), |st| *st.session.as_ref().unwrap().origin_ek());
    // Stray records after the exchange: ignored.
    for kind in [KIND_INIT, KIND_RESP, KIND_CONFIRM] {
        assert!(init
            .core
            .pq
            .on_record(&resp.id(), &sid, &[kind, 1, 2, 3], 5_000)
            .is_ok());
    }
    assert_eq!(state_of(init, resp).0, "hybrid");
}

#[test]
fn a_status_shows_what_happened() {
    let a = side();
    let b = side();
    mode(&a, PqcMode::Prefer);
    mode(&b, PqcMode::Prefer);
    a.core.enqueue(&b.id(), "x", 1).unwrap();
    pump(&a, &b, 1_000);
    let s = crate::chat::ipc::pqc_status_for(PqcMode::Prefer);
    assert_eq!(s.mode, "prefer");
    assert!(s.available);
    assert!(s.counts.hybrid_sessions >= 2);
}

// ─── Typed refusals carry the right reason ──────────────────────────────────

/// The two refusal kinds map to the two distinct reason strings, and each one
/// carries the contact it is about. This is the out-of-band contract the
/// delivery workers (private and group) rely on to show the person *why* a
/// message was refused under `require`.
#[test]
fn the_two_refusals_carry_their_distinct_reason_and_the_contact() {
    let peer = [7u8; 32];
    let lacks = PqcRefusal::PeerLacksPqc { peer };
    let downgrade = PqcRefusal::PqcDowngradeRefused { peer };
    // Distinct, stable strings.
    assert_eq!(lacks.reason_str(), FAIL_NO_HYBRID);
    assert_eq!(downgrade.reason_str(), FAIL_EXCHANGE);
    assert_ne!(lacks.reason_str(), downgrade.reason_str());
    // Each refusal names its contact.
    assert_eq!(lacks.peer(), &peer);
    assert_eq!(downgrade.peer(), &peer);
}

/// A `require` peer whose ML-KEM response is corrupted must fail the message
/// with the *exchange* reason (`PqcDowngradeRefused` -> `FAIL_EXCHANGE`), not
/// the *no-hybrid* reason: the peer did offer the suite, the exchange is what
/// broke. Nothing is sent in the clear.
#[test]
fn require_with_a_tampered_mlkem_part_fails_with_the_exchange_reason() {
    let a = side();
    let b = side();
    mode(&a, PqcMode::Require);
    mode(&b, PqcMode::Prefer);
    let (init, resp) = roles(&a, &b);
    let hook = |kind: u8, plain: &mut Vec<u8>| {
        if kind == KIND_RESP {
            let n = plain.len();
            plain[n - 1] ^= 0x01;
        }
    };
    let (req_side, other) = if init.core.pqc_mode() == PqcMode::Require {
        (init, resp)
    } else {
        (resp, init)
    };
    req_side.core.enqueue(&other.id(), "secret", 1).unwrap();
    pump_with(init, resp, Peer::Current, 1_000, Some(&hook));
    assert!(
        other.texts(&req_side.id()).is_empty(),
        "no classical fallback under require"
    );
    let hist = req_side.core.history(&other.id(), None, 10);
    assert_eq!(hist[0].state, MsgState::Failed);
    assert_eq!(
        hist[0].reason.as_deref(),
        Some(FAIL_EXCHANGE),
        "a broken exchange is the exchange reason, not no-hybrid"
    );
}

/// A `require` peer whose offer is forged (a capability set that does not match
/// what it actually sends) is caught by the transcript binding and refused with
/// the *exchange* reason. The message is never sent classically.
#[test]
fn require_with_a_forged_offer_fails_with_the_exchange_reason() {
    let a = side();
    let b = side();
    mode(&a, PqcMode::Require);
    mode(&b, PqcMode::Prefer);
    let (init, resp) = roles(&a, &b);
    let altered = Capabilities::current()
        .with_unknown(vec![1, 2, 3])
        .unwrap()
        .encode();
    let alter = std::cell::Cell::new(false);
    let hook = |kind: u8, plain: &mut Vec<u8>| {
        if kind == KIND_OFFER && alter.get() {
            plain.truncate(1);
            plain.extend_from_slice(&altered);
            alter.set(false);
        }
    };
    init.core.enqueue(&resp.id(), "secret", 1).unwrap();
    assert!(step(init, resp, Peer::Current, 1_000, Some(&hook)));
    alter.set(true);
    assert!(step(resp, init, Peer::Current, 1_000, Some(&hook)));
    pump_with(init, resp, Peer::Current, 1_000, Some(&hook));
    let (req_side, other) = if init.core.pqc_mode() == PqcMode::Require {
        (init, resp)
    } else {
        (resp, init)
    };
    assert!(
        other.texts(&req_side.id()).is_empty(),
        "no classical fallback under require"
    );
    let hist = req_side.core.history(&other.id(), None, 10);
    assert_eq!(hist[0].state, MsgState::Failed);
    assert_eq!(hist[0].reason.as_deref(), Some(FAIL_EXCHANGE));
}
