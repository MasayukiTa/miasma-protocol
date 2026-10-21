//! A build that offers the hybrid upgrade keeps talking to a peer that does not
//! know it (feature `pqc`).
//!
//! The peer is simulated with **frozen copies of the decoders** of the earlier
//! releases (the envelope reader below, and the frame and message readers of
//! `old_chat`, copied from `wire_compat_test.rs`), which are strict: unknown
//! trailing bytes or an unknown record kind are errors. Whatever this build
//! puts on the wire towards such a peer must pass them. The session crypto of
//! the old peer is the unlayered ratchet, which this build still uses
//! unchanged whenever no hybrid key was agreed.
//!
//! Two kinds of old peer are simulated:
//!
//! * `strict`: the release that answers "bad request" for any record kind
//!   other than a text (and does not move its session for it);
//! * tolerant: a later release that acknowledges and sets such a record aside.
//!
//! What this cannot show: that a real old binary behaves like the copies. They
//! are copied from the sources of those releases.

#![cfg(feature = "pqc")]

use std::{path::Path, sync::Arc};

use miasma_core::{
    chat::{
        crypto::{Envelope, Identity, Session},
        engine::ChatCore,
        outbox::Outbox,
        pq::{Pass, SendOutcome, OFFER_WAIT_MS},
        proto::{encode_frame, AckStatus, Frame},
        store::{ChatStore, StoreSettings},
    },
    config::PqcMode,
    state_crypto::StateKeys,
};

// ─── Decoders of the earlier releases (copied from their sources) ───────────

/// A bounds-checked cursor, as in the releases.
struct Rd<'a>(&'a [u8], usize);

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Rd(b, 0)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.1.checked_add(n)?;
        let s = self.0.get(self.1..end)?;
        self.1 = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|s| u64::from_be_bytes(s.try_into().unwrap()))
    }
    fn arr16(&mut self) -> Option<[u8; 16]> {
        self.take(16).map(|s| s.try_into().unwrap())
    }
    fn pos(&self) -> usize {
        self.1
    }
    fn done(&self) -> bool {
        self.1 == self.0.len()
    }
}

/// The frame and text readers of the one-to-one chat of v0.3.2-beta.2.
mod old_chat {
    use super::Rd;

    /// A `Deliver` frame (type 1); anything else is an error.
    pub fn decode_deliver(b: &[u8]) -> Result<Vec<u8>, &'static str> {
        if b.len() < 5 {
            return Err("short");
        }
        let len = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if len == 0 || b.len() < 4 + len {
            return Err("length");
        }
        let (&ty, payload) = b[4..4 + len].split_first().unwrap();
        match ty {
            1 => Ok(payload.to_vec()),
            _ => Err("type"),
        }
    }

    /// Kind 1 only; any other kind is "malformed message kind" and is
    /// answered with a bad-request acknowledgement.
    pub fn decode_message(b: &[u8]) -> Result<String, &'static str> {
        let mut r = Rd::new(b);
        if r.u8().ok_or("m")? != 1 {
            return Err("message kind");
        }
        let _id = r.arr16().ok_or("m")?;
        let seq = r.u64().ok_or("m")?;
        let _sent = r.u64().ok_or("m")?;
        let n = r.u16().ok_or("m")? as usize;
        if n == 0 || n > 4096 {
            return Err("text length");
        }
        let text = std::str::from_utf8(r.take(n).ok_or("m")?)
            .map_err(|_| "text encoding")?
            .to_owned();
        if !r.done() || seq == 0 {
            return Err("message");
        }
        Ok(text)
    }
}

/// The envelope reader of the same releases (`chat/crypto.rs`): strict about
/// every length, the first-flight flag byte (0 or 1 only) and trailing bytes.
mod old_envelope {
    use super::Rd;

    pub fn decode(b: &[u8]) -> Result<(), &'static str> {
        let mut r = Rd::new(b);
        if r.u8().ok_or("short")? != 1 {
            return Err("version");
        }
        if r.u8().ok_or("short")? != 2 || r.u8().ok_or("short")? != 1 {
            return Err("suite or kind");
        }
        r.take(16).ok_or("short")?; // envelope id
        r.take(32).ok_or("short")?; // ratchet key
        r.take(8).ok_or("short")?; // pn, n
        match r.u8().ok_or("short")? {
            0 => {}
            1 => {
                r.take(32).ok_or("short")?;
            }
            _ => return Err("init flag"),
        }
        if r.pos() > 1024 {
            return Err("header");
        }
        let ct_len = u32::from_be_bytes(r.take(4).ok_or("short")?.try_into().unwrap()) as usize;
        if !(16..=16384 + 16).contains(&ct_len) {
            return Err("ciphertext length");
        }
        r.take(ct_len).ok_or("short")?;
        if !r.done() {
            return Err("trailing bytes");
        }
        Ok(())
    }
}

// ─── The simulated old peer ─────────────────────────────────────────────────

struct OldPeer {
    me: Identity,
    session: Option<Session>,
    /// Answers "bad request" for a record it does not know and keeps its
    /// session as it was (otherwise it acknowledges and sets the record aside).
    strict: bool,
    texts: Vec<String>,
    /// Every envelope it was handed, to check their shape afterwards.
    seen: Vec<Vec<u8>>,
}

impl OldPeer {
    fn new(strict: bool) -> Self {
        Self {
            me: Identity::from_seed(&rand::random()),
            session: None,
            strict,
            texts: Vec::new(),
            seen: Vec::new(),
        }
    }

    fn id(&self) -> [u8; 32] {
        self.me.id()
    }

    fn receive(&mut self, from: &[u8; 32], wire: &[u8]) -> AckStatus {
        // The frame this build writes is read by the frozen frame reader.
        let frame = encode_frame(&Frame::Deliver(wire.to_vec()));
        assert_eq!(old_chat::decode_deliver(&frame).unwrap(), wire);
        // The envelope passes the frozen strict reader and is the same bytes
        // the current codec writes for it.
        old_envelope::decode(wire).expect("the frozen envelope reader reads it");
        let env = Envelope::decode(wire).unwrap();
        assert_eq!(env.encode(), wire, "the envelope shape is canonical");
        self.seen.push(wire.to_vec());
        let (session, pt) = match &self.session {
            Some(s) => {
                let mut s = s.clone();
                let pt = s.open(&env).expect("the old peer opens it");
                (s, pt)
            }
            None => Session::accept(&self.me, from, &env).expect("the old peer opens it"),
        };
        match old_chat::decode_message(&pt) {
            Ok(text) => {
                self.session = Some(session);
                self.texts.push(text);
                AckStatus::Stored
            }
            Err(_) if self.strict => AckStatus::BadRequest,
            Err(_) => {
                self.session = Some(session);
                AckStatus::Stored
            }
        }
    }

    fn reply(&mut self, text: &str, to: &ChatCore) {
        use miasma_core::chat::proto::Message;
        let m = Message {
            id: rand::random(),
            seq: 1,
            sent_ms: 1,
            text: text.to_owned(),
        };
        let env = self
            .session
            .as_mut()
            .expect("a session")
            .seal(&m.encode().unwrap())
            .unwrap();
        let st = to.accept(&self.id(), &env.encode(), 7).status;
        assert!(st.is_delivered(), "{st:?}");
    }
}

fn core_in(dir: &Path, mode: PqcMode) -> ChatCore {
    let seed: [u8; 32] = rand::random();
    let keys = Arc::new(StateKeys::open_or_init(dir).unwrap());
    let id = Identity::from_seed(&seed);
    let chat = dir.join("chat");
    let s = StoreSettings::default();
    let store = ChatStore::open(&chat, keys.clone(), id.id(), s.clone()).unwrap();
    let (outbox, _) = Outbox::open(&miasma_core::paths::chat_outbox_file(&chat), keys, s, 1);
    let core = ChatCore::new(store, outbox, id, 4096);
    core.set_pqc_mode(mode);
    core
}

/// The delivery loop of `core` towards the old peer, as the worker runs it.
fn drive(core: &ChatCore, old: &mut OldPeer, now: u64) {
    let peer = old.id();
    for _ in 0..50 {
        let have_text = core.outbox.first_for(&peer).is_some();
        match core.pq_step(&peer, have_text, now) {
            Pass::Send(out) => {
                let (wire, _) = core.seal_for(&peer, &out.plain).unwrap();
                let outcome = match old.receive(&core.own_id(), &wire) {
                    AckStatus::Stored | AckStatus::Duplicate => SendOutcome::Delivered,
                    AckStatus::BadRequest => SendOutcome::NotUnderstood,
                    other => panic!("unexpected answer {other:?}"),
                };
                core.pq_sent(&peer, &out, outcome, now);
            }
            Pass::Proceed => {
                let Some(e) = core.outbox.first_for(&peer) else {
                    return;
                };
                let (wire, _) = core.prepare_wire(&e.id).unwrap();
                assert_eq!(old.receive(&core.own_id(), &wire), AckStatus::Stored);
                core.mark_delivered(&e.id, now);
            }
            other => panic!("`prefer` never holds or refuses: {other:?}"),
        }
    }
    panic!("does not settle");
}

/// The delivery loop under `require`. Offers go to the old peer; messages are
/// never sent unless the hybrid key is agreed. Returns the reason the waiting
/// messages are failed with, once the build gives up on the contact.
fn drive_require(core: &ChatCore, old: &mut OldPeer, now: u64) -> Option<&'static str> {
    let peer = old.id();
    for _ in 0..50 {
        let have_text = core.outbox.first_for(&peer).is_some();
        match core.pq_step(&peer, have_text, now) {
            Pass::Send(out) => {
                let (wire, _) = core.seal_for(&peer, &out.plain).unwrap();
                let outcome = match old.receive(&core.own_id(), &wire) {
                    AckStatus::Stored | AckStatus::Duplicate => SendOutcome::Delivered,
                    AckStatus::BadRequest => SendOutcome::NotUnderstood,
                    other => panic!("unexpected answer {other:?}"),
                };
                core.pq_sent(&peer, &out, outcome, now);
            }
            Pass::Hold => return None,
            Pass::Refuse(reason) => return Some(reason),
            Pass::Proceed => panic!("`require` must not send a text without the hybrid key"),
        }
    }
    panic!("does not settle");
}

fn no_hybrid_key(core: &ChatCore, old: &OldPeer) -> bool {
    let sid = core
        .store
        .peek_peer(&old.id(), |st| *st.session.as_ref().unwrap().origin_ek());
    core.pq.seal_key(&old.id(), &sid).is_none() && core.pq.open_key(&old.id(), &sid).is_none()
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[test]
fn an_offering_build_and_a_strict_old_peer_keep_talking() {
    let dir = tempfile::tempdir().unwrap();
    let core = core_in(dir.path(), PqcMode::Prefer);
    let mut old = OldPeer::new(true);
    core.enqueue(&old.id(), "hello", 1).unwrap();
    core.enqueue(&old.id(), "second", 2).unwrap();
    drive(&core, &mut old, 1_000);
    // Both texts arrived, in order, through the old readers.
    assert_eq!(old.texts, ["hello", "second"]);
    // The offer was refused as unknown: classical only, with the reason.
    let v = core.pq_view(&old.id());
    assert_eq!((v.state, v.reason), ("classical", Some("peer_old_build")));
    assert!(no_hybrid_key(&core, &old));
    // The old peer answers in the same session.
    old.reply("back", &core);
    let hist = core.history(&old.id(), None, 10);
    assert!(hist.iter().any(|m| m.text == "back"));
}

#[test]
fn an_offering_build_and_a_tolerant_old_peer_keep_talking() {
    let dir = tempfile::tempdir().unwrap();
    let core = core_in(dir.path(), PqcMode::Prefer);
    let mut old = OldPeer::new(false);
    core.enqueue(&old.id(), "hello", 1).unwrap();
    drive(&core, &mut old, 1_000);
    assert_eq!(old.texts, ["hello"]);
    // Acknowledged and set aside: no answer ever comes, so after the wait the
    // session is shown as classical only.
    assert_eq!(core.pq_view(&old.id()).state, "pending");
    core.enqueue(&old.id(), "later", 2).unwrap();
    drive(&core, &mut old, 1_000 + OFFER_WAIT_MS + 1);
    let v = core.pq_view(&old.id());
    assert_eq!((v.state, v.reason), ("classical", Some("peer_no_hybrid")));
    assert_eq!(old.texts, ["hello", "later"]);
    assert!(no_hybrid_key(&core, &old));
    old.reply("back", &core);
    assert!(core
        .history(&old.id(), None, 10)
        .iter()
        .any(|m| m.text == "back"));
}

#[test]
fn require_never_downgrades_towards_a_strict_old_peer() {
    let dir = tempfile::tempdir().unwrap();
    let core = core_in(dir.path(), PqcMode::Require);
    let mut old = OldPeer::new(true);
    core.enqueue(&old.id(), "secret", 1).unwrap();
    // The old peer refuses the offer as unknown: the waiting message is failed
    // with the stable reason that the interface turns into a plain sentence.
    let reason = drive_require(&core, &mut old, 1_000);
    assert_eq!(reason, Some(miasma_core::chat::pq::FAIL_NO_HYBRID));
    // The text never reached the old peer, in any session.
    assert!(old.texts.is_empty());
    assert!(no_hybrid_key(&core, &old));
    // Asking again does not change the answer.
    assert_eq!(
        drive_require(&core, &mut old, 2_000),
        Some(miasma_core::chat::pq::FAIL_NO_HYBRID)
    );
    assert!(old.texts.is_empty());
}

#[test]
fn require_never_downgrades_towards_a_tolerant_old_peer() {
    let dir = tempfile::tempdir().unwrap();
    let core = core_in(dir.path(), PqcMode::Require);
    let mut old = OldPeer::new(false);
    core.enqueue(&old.id(), "secret", 1).unwrap();
    // The offer is acknowledged and set aside; the message waits for an answer.
    assert_eq!(drive_require(&core, &mut old, 1_000), None);
    assert!(old.texts.is_empty());
    // No answer ever comes: after the wait the message is failed, not sent.
    let reason = drive_require(&core, &mut old, 1_000 + OFFER_WAIT_MS + 1);
    assert_eq!(reason, Some(miasma_core::chat::pq::FAIL_NO_HYBRID));
    assert!(old.texts.is_empty());
    assert!(no_hybrid_key(&core, &old));
}

#[test]
fn a_build_with_the_setting_off_sends_exactly_what_it_always_sent() {
    let dir = tempfile::tempdir().unwrap();
    let core = core_in(dir.path(), PqcMode::Off);
    let mut old = OldPeer::new(true);
    core.enqueue(&old.id(), "hello", 1).unwrap();
    drive(&core, &mut old, 1_000);
    // One envelope, the text: no offer, no state, no file.
    assert_eq!(old.seen.len(), 1);
    assert_eq!(old.texts, ["hello"]);
    assert_eq!(core.pq_view(&old.id()).state, "off");
    let chat = dir.path().join("chat");
    let pq_files = std::fs::read_dir(&chat)
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "pq"))
        .count();
    assert_eq!(pq_files, 0);
}

#[test]
fn the_first_envelope_to_a_strict_old_peer_may_be_the_offer_and_the_text_still_starts_the_session()
{
    // The offer is the first flight of the session; the old peer refuses it
    // without keeping anything, and the next envelope still carries the
    // first-flight key, so it starts the session by itself.
    let dir = tempfile::tempdir().unwrap();
    let core = core_in(dir.path(), PqcMode::Prefer);
    let mut old = OldPeer::new(true);
    core.enqueue(&old.id(), "x", 1).unwrap();
    drive(&core, &mut old, 1_000);
    assert!(old.seen.len() >= 2);
    let first = Envelope::decode(&old.seen[0]).unwrap();
    let second = Envelope::decode(&old.seen[1]).unwrap();
    assert!(first.header.init_ek.is_some() && second.header.init_ek.is_some());
    assert_eq!(first.header.init_ek, second.header.init_ek);
    assert_eq!(old.texts, ["x"]);
}

/// Two builds that agreed on the hybrid upgrade: the layered envelope has the
/// same shape as any other, and the session of an old peer never gets one.
#[test]
fn layered_envelopes_have_the_common_shape_and_never_reach_a_peer_without_the_key() {
    let da = tempfile::tempdir().unwrap();
    let db = tempfile::tempdir().unwrap();
    let a = core_in(da.path(), PqcMode::Prefer);
    let b = core_in(db.path(), PqcMode::Prefer);
    let now = 1_000;
    a.enqueue(&b.own_id(), "one", 1).unwrap();
    for _ in 0..400 {
        let mut any = false;
        for (from, to) in [(&a, &b), (&b, &a)] {
            let peer = to.own_id();
            let have_text = from.outbox.first_for(&peer).is_some();
            match from.pq_step(&peer, have_text, now) {
                Pass::Send(out) => {
                    let (wire, _) = from.seal_for(&peer, &out.plain).unwrap();
                    assert!(to.accept(&from.own_id(), &wire, now).status.is_delivered());
                    from.pq_sent(&peer, &out, SendOutcome::Delivered, now);
                    any = true;
                }
                Pass::Proceed => {
                    if let Some(e) = from.outbox.first_for(&peer) {
                        let (wire, _) = from.prepare_wire(&e.id).unwrap();
                        assert!(to.accept(&from.own_id(), &wire, now).status.is_delivered());
                        from.mark_delivered(&e.id, now);
                        any = true;
                    }
                }
                other => panic!("{other:?}"),
            }
        }
        if !any {
            break;
        }
    }
    assert_eq!(a.pq_view(&b.own_id()).state, "hybrid");
    let id = a.enqueue(&b.own_id(), "layered", 9).unwrap();
    let (wire, _) = a.prepare_wire(&id).unwrap();
    // Same shape: the frozen reader reads it, the codec writes the same bytes.
    old_envelope::decode(&wire).expect("same shape as every envelope");
    assert_eq!(Envelope::decode(&wire).unwrap().encode(), wire);
    // A peer that does not hold the key cannot open it: which is why it is
    // only ever produced once the peer proved it holds the key.
    let env = Envelope::decode(&wire).unwrap();
    let mut s = b
        .store
        .peek_peer(&a.own_id(), |st| st.session.clone().unwrap());
    assert!(s.open(&env).is_err());
}
