//! The chat engine without the network: it joins the cipher, the stores and
//! the outbox, and decides what happens to a message in each direction. The
//! service feeds it connections; the tests feed it directly.
//!
//! Ordering rules that keep delivery idempotent and keys single-use:
//!
//! * One gate serialises everything that touches a session. A ratchet step is
//!   written to disk before the envelope that used it leaves the process.
//! * On receiving: decrypt on a copy of the session, write the message to the
//!   history, and only then commit the session, the sequence number and the
//!   envelope ID. A failure in between leaves the old state, so the sender's
//!   retry is processed again (a rare duplicate record is preferred to a lost
//!   message).
//! * A sequence number is applied once; a repeated one, or the same envelope
//!   again after a lost acknowledgement, is answered as a duplicate.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex, MutexGuard,
    },
};

use super::{
    crypto::{CryptoError, Envelope, Identity, Session},
    outbox::{new_entry, new_receipt, OutEntry, OutKind, Outbox},
    proto::{AckStatus, Message, ReadReceipt, Record, MAX_TEXT_BYTES},
    store::{ChatStore, MsgState, NewMessage, StoreError, StoredMessage},
};

/// At most one read receipt per contact in this many milliseconds.
pub const RECEIPT_MIN_INTERVAL_MS: u64 = 5_000;
/// Contacts whose last receipt time is remembered (the map is cleared above it).
const RECEIPT_CLOCK_CAP: usize = 1024;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnqueueError {
    Empty,
    TooBig,
    OutboxFull,
    Storage(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareError {
    /// The entry is gone (delivered or cancelled meanwhile).
    Gone,
    /// The session cannot be started (the peer's key is unusable).
    Session(String),
    Storage(String),
}

/// What happened, for a client that follows the conversation.
#[derive(Debug, Clone)]
pub struct ChatEvent {
    pub seq: u64,
    pub peer: [u8; 32],
    pub kind: EventKind,
    pub message: StoredMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Received,
    Delivered,
    Failed,
    /// The contact read our messages; `message.seq` is the number it read up
    /// to (the other fields of `message` carry no content).
    Read,
}

/// What [`ChatCore::mark_read`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkOutcome {
    /// A receipt was queued.
    Queued,
    /// Nothing to report (already reported, or nothing received).
    Nothing,
    /// Too soon after the last receipt to this contact: ask again later.
    TooSoon,
    /// Read receipts are off, for everyone or for this contact.
    Disabled,
}

const EVENT_CAP: usize = 200;

struct Events {
    next: u64,
    items: VecDeque<ChatEvent>,
}

pub struct AcceptOutcome {
    pub status: AckStatus,
    /// The session was replaced: sealed envelopes cached for the peer are void.
    pub session_replaced: bool,
}

pub struct ChatCore {
    pub store: ChatStore,
    pub outbox: Outbox,
    identity: Identity,
    max_text: usize,
    gate: Mutex<()>,
    events: Mutex<Events>,
    /// Global switch for read receipts (`chat.read_receipts`).
    receipts_global: AtomicBool,
    receipt_interval_ms: AtomicU64,
    /// When the last receipt for each contact was queued.
    receipt_clock: Mutex<HashMap<[u8; 32], u64>>,
}

impl ChatCore {
    pub fn new(
        store: ChatStore,
        outbox: Outbox,
        identity: Identity,
        max_message_bytes: usize,
    ) -> Self {
        Self {
            store,
            outbox,
            identity,
            max_text: max_message_bytes.clamp(1, MAX_TEXT_BYTES),
            gate: Mutex::new(()),
            events: Mutex::new(Events {
                next: 1,
                items: VecDeque::new(),
            }),
            receipts_global: AtomicBool::new(true),
            receipt_interval_ms: AtomicU64::new(RECEIPT_MIN_INTERVAL_MS),
            receipt_clock: Mutex::new(HashMap::new()),
        }
    }

    // ── Read receipts: switches ──────────────────────────────────────────────

    /// Set the global switch (`chat.read_receipts`).
    pub fn set_receipts_global(&self, on: bool) {
        self.receipts_global.store(on, Ordering::Relaxed);
    }

    pub fn receipts_global(&self) -> bool {
        self.receipts_global.load(Ordering::Relaxed)
    }

    /// Change the shortest time between two receipts to one contact.
    pub fn set_receipt_interval_ms(&self, ms: u64) {
        self.receipt_interval_ms.store(ms, Ordering::Relaxed);
    }

    /// Receipts are sent to, and shown from, `peer` only when both the global
    /// switch and the switch of this contact are on. With either off nothing
    /// is sent, what arrives is not kept, and what was kept is not shown.
    pub fn receipts_enabled(&self, peer: &[u8; 32]) -> bool {
        self.receipts_global() && !self.store.peek_peer(peer, |st| st.receipts_off)
    }

    /// Switch read receipts on or off for one contact. Switching off also
    /// drops a receipt that is still waiting to go out.
    pub fn set_receipts(&self, peer: &[u8; 32], on: bool) -> Result<(), StoreError> {
        let _g = self.gate();
        self.store.with_peer(peer, |st| st.receipts_off = !on);
        self.store.flush_peer(peer)?;
        if !on {
            if let Some(e) = self.outbox.receipt_for(peer) {
                self.outbox.remove(&e.id);
            }
        }
        Ok(())
    }

    /// The person is looking at the conversation with `peer` and has seen the
    /// messages received from it up to number `up_to`: tell the contact, once
    /// per advance and at most once per interval. A receipt for a receipt is
    /// impossible by construction: only text numbers are ever reported.
    pub fn mark_read(
        &self,
        peer: &[u8; 32],
        up_to: u64,
        now: u64,
    ) -> Result<MarkOutcome, StoreError> {
        let _g = self.gate();
        if !self.receipts_enabled(peer) {
            return Ok(MarkOutcome::Disabled);
        }
        let (newest, reported) = self
            .store
            .peek_peer(peer, |st| (st.max_recv_seq(), st.read_reported));
        let up_to = up_to.min(newest);
        if up_to == 0 || up_to <= reported {
            return Ok(MarkOutcome::Nothing);
        }
        let interval = self.receipt_interval_ms.load(Ordering::Relaxed);
        {
            let clock = self.receipt_clock.lock().unwrap();
            if let Some(&last) = clock.get(peer) {
                if now.saturating_sub(last) < interval {
                    return Ok(MarkOutcome::TooSoon);
                }
            }
        }
        self.outbox
            .push_receipt(new_receipt(rand::random(), *peer, up_to, now))?;
        self.store.with_peer(peer, |st| st.read_reported = up_to);
        self.store.flush_peer(peer)?;
        let mut clock = self.receipt_clock.lock().unwrap();
        if clock.len() >= RECEIPT_CLOCK_CAP {
            clock.clear();
        }
        clock.insert(*peer, now);
        Ok(MarkOutcome::Queued)
    }

    /// True when a queued receipt has outlived its expiry.
    pub fn receipt_expired(&self, e: &OutEntry, now: u64) -> bool {
        e.kind == OutKind::Read
            && now.saturating_sub(e.created_ms) > self.store.settings().receipt_expiry_ms
    }

    pub fn own_id(&self) -> [u8; 32] {
        self.identity.id()
    }

    pub fn max_text(&self) -> usize {
        self.max_text
    }

    fn gate(&self) -> MutexGuard<'_, ()> {
        self.gate.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn push_event(&self, peer: [u8; 32], kind: EventKind, message: StoredMessage) {
        let mut e = self.events.lock().unwrap();
        let seq = e.next;
        e.next += 1;
        if e.items.len() >= EVENT_CAP {
            e.items.pop_front();
        }
        e.items.push_back(ChatEvent {
            seq,
            peer,
            kind,
            message,
        });
    }

    /// Events with a number above `since`, and the number to ask from next.
    pub fn events_since(&self, since: u64) -> (u64, Vec<ChatEvent>) {
        let e = self.events.lock().unwrap();
        (
            e.next - 1,
            e.items.iter().filter(|x| x.seq > since).cloned().collect(),
        )
    }

    // ── Sending ──────────────────────────────────────────────────────────────

    /// Accept a message from the user: assign its number, write it to the
    /// outbox (durable) and return its ID.
    pub fn enqueue(&self, peer: &[u8; 32], text: &str, now: u64) -> Result<[u8; 16], EnqueueError> {
        if text.is_empty() {
            return Err(EnqueueError::Empty);
        }
        if text.len() > self.max_text {
            return Err(EnqueueError::TooBig);
        }
        let _g = self.gate();
        if self.outbox.text_len() >= self.store.settings().outbox_max {
            return Err(EnqueueError::OutboxFull);
        }
        let seq = self.store.with_peer(peer, |p| p.next_seq());
        // The number is written first: after a crash it may be skipped, never
        // given twice.
        self.store
            .flush_peer(peer)
            .map_err(|e| EnqueueError::Storage(e.to_string()))?;
        let id: [u8; 16] = rand::random();
        self.outbox
            .push(new_entry(id, *peer, seq, now, text.to_owned()))
            .map_err(|e| match e {
                StoreError::OutboxFull => EnqueueError::OutboxFull,
                other => EnqueueError::Storage(other.to_string()),
            })?;
        Ok(id)
    }

    /// The bytes to put on the wire for outbox entry `id`. The first call
    /// advances the ratchet and writes the new state and the sealed envelope
    /// to disk; later calls (retries, also after a restart) return the same
    /// bytes.
    pub fn prepare_wire(&self, id: &[u8; 16]) -> Result<(Vec<u8>, [u8; 16]), PrepareError> {
        let _g = self.gate();
        let e = self.outbox.get(id).ok_or(PrepareError::Gone)?;
        if let Some(s) = &e.sealed {
            if let Ok(env) = Envelope::decode(s) {
                return Ok((s.clone(), env.id));
            }
        }
        if !self.outbox.has_sealed_room() {
            return Err(PrepareError::Storage("sealed envelope budget".into()));
        }
        let plain = match e.kind {
            OutKind::Text => Message {
                id: e.id,
                seq: e.seq,
                sent_ms: e.sent_ms,
                text: e.text.clone(),
            }
            .encode(),
            OutKind::Read => ReadReceipt {
                id: e.id,
                up_to_seq: e.seq,
            }
            .encode(),
        }
        .map_err(|er| PrepareError::Session(er.to_string()))?;
        let peer = e.peer;
        let me = &self.identity;
        let env = self
            .store
            .with_peer(&peer, |st| -> Result<Envelope, CryptoError> {
                if st.session.is_none() {
                    st.session = Some(Session::new_initiator(me, &peer)?);
                }
                st.session.as_mut().expect("set above").seal(&plain)
            })
            .map_err(|er| PrepareError::Session(er.to_string()))?;
        // The used key must not be forgotten if we crash after sending.
        self.store
            .flush_peer(&peer)
            .map_err(|er| PrepareError::Storage(er.to_string()))?;
        let bytes = env.encode();
        // Written down before the bytes leave: a restart then resends these
        // exact bytes instead of sealing again with the next key. If it cannot
        // be written the message is not sent now (the key stays used; the
        // receiver keeps keys for messages it has not seen, up to a bound).
        self.outbox
            .set_sealed(id, &bytes)
            .map_err(|er| PrepareError::Storage(er.to_string()))?;
        Ok((bytes, env.id))
    }

    /// Forget the session with `peer` (it told us it has none) and void the
    /// sealed envelopes cached for it; the next attempt starts a new one.
    pub fn reset_session(&self, peer: &[u8; 32]) {
        let _g = self.gate();
        self.store.with_peer(peer, |st| st.session = None);
        let _ = self.store.flush_peer(peer);
        self.void_sealed(peer);
    }

    fn void_sealed(&self, peer: &[u8; 32]) {
        for e in self.outbox.pending_for(peer) {
            self.outbox.clear_sealed(&e.id);
        }
    }

    fn stored_from(e: &OutEntry, state: MsgState, reason: Option<String>, at: u64) -> NewMessage {
        NewMessage {
            outgoing: true,
            id: e.id,
            seq: e.seq,
            sent_ms: e.sent_ms,
            at_ms: at,
            state,
            reason,
            text: e.text.clone(),
        }
    }

    /// The receiver has the message: move it to the history as delivered.
    pub fn mark_delivered(&self, id: &[u8; 16], now: u64) {
        self.finish(id, MsgState::Delivered, None, now);
    }

    /// The message will not be delivered; keep it in the history as failed.
    pub fn mark_failed(&self, id: &[u8; 16], reason: &str, now: u64) {
        self.finish(id, MsgState::Failed, Some(reason.to_owned()), now);
    }

    fn finish(&self, id: &[u8; 16], state: MsgState, reason: Option<String>, now: u64) {
        let Some(e) = self.outbox.get(id) else { return };
        if e.kind == OutKind::Read {
            // A receipt leaves no trace: delivered or given up, it just goes.
            self.outbox.remove(id);
            return;
        }
        let nm = Self::stored_from(&e, state, reason.clone(), now);
        match self.store.record(&e.peer, nm, false) {
            Ok(ord) => {
                self.outbox.remove(id);
                let kind = if state == MsgState::Delivered {
                    EventKind::Delivered
                } else {
                    EventKind::Failed
                };
                self.push_event(
                    e.peer,
                    kind,
                    StoredMessage {
                        ord,
                        outgoing: true,
                        id: e.id,
                        seq: e.seq,
                        sent_ms: e.sent_ms,
                        at_ms: now,
                        state,
                        reason,
                        text: e.text.clone(),
                    },
                );
            }
            Err(er) => {
                // Keep it in the outbox; the next attempt finishes it.
                self.outbox
                    .update(id, |x| x.last_error = Some(er.to_string()));
            }
        }
    }

    /// A page of the conversation with the queued messages at its end.
    pub fn history(
        &self,
        peer: &[u8; 32],
        before: Option<u64>,
        limit: usize,
    ) -> Vec<StoredMessage> {
        let pending = self
            .outbox
            .pending_for(peer)
            .into_iter()
            .filter(|e| e.kind == OutKind::Text)
            .map(|e| StoredMessage {
                ord: 0,
                outgoing: true,
                id: e.id,
                seq: e.seq,
                sent_ms: e.sent_ms,
                at_ms: e.created_ms,
                state: if e.sending {
                    MsgState::Sending
                } else {
                    MsgState::Queued
                },
                reason: e.last_error.clone(),
                text: e.text.clone(),
            })
            .collect();
        let mut page = self.store.history(peer, before, limit, pending);
        // A delivered message the contact has read is shown as read, unless
        // receipts are off (then what the contact told us stays hidden).
        if self.receipts_enabled(peer) {
            let read_up_to = self.store.peek_peer(peer, |st| st.read_up_to);
            if read_up_to > 0 {
                for m in page.iter_mut() {
                    if m.outgoing && m.state == MsgState::Delivered && m.seq <= read_up_to {
                        m.state = MsgState::Read;
                    }
                }
            }
        }
        page
    }

    /// Delete one message locally: from the history, or cancel it when it is
    /// still queued. True when something was removed.
    pub fn delete_message(&self, peer: &[u8; 32], id: &[u8; 16]) -> Result<bool, StoreError> {
        let _g = self.gate();
        let cancelled = self.outbox.remove(id).is_some();
        let removed = self.store.delete_message(peer, id)?;
        Ok(cancelled || removed)
    }

    /// Delete the whole conversation locally, queued messages included.
    pub fn delete_conversation(&self, peer: &[u8; 32]) -> Result<(), StoreError> {
        let _g = self.gate();
        self.outbox.remove_peer(peer);
        self.store.delete_conversation(peer)?;
        self.store.flush_peer(peer)
    }

    // ── Receiving ────────────────────────────────────────────────────────────

    /// Apply an envelope that arrived from `peer` (already authenticated by the
    /// transport and allowed by the contact list).
    pub fn accept(&self, peer: &[u8; 32], wire: &[u8], now: u64) -> AcceptOutcome {
        let plain = |status| AcceptOutcome {
            status,
            session_replaced: false,
        };
        let env = match Envelope::decode(wire) {
            Ok(e) => e,
            Err(CryptoError::Version(_)) | Err(CryptoError::Unsupported) => {
                return plain(AckStatus::Unsupported)
            }
            Err(_) => return plain(AckStatus::BadRequest),
        };
        let _g = self.gate();

        // Step 1: decide on copies; nothing is changed yet.
        enum Step {
            Done(AckStatus),
            Open {
                session: Session,
                record: Record,
                replaced: bool,
                new_ek: Option<[u8; 32]>,
            },
        }
        let me = &self.identity;
        let max_text = self.max_text;
        let step = self.store.peek_peer(peer, |st| -> Step {
            if st.recent_env.contains(&env.id) {
                return Step::Done(AckStatus::Duplicate);
            }
            let mut replaced = false;
            let mut new_ek = None;
            let result: Option<Result<(Session, zeroize::Zeroizing<Vec<u8>>), CryptoError>>;
            if let Some(existing) = &st.session {
                let mut s = existing.clone();
                match s.open(&env) {
                    Ok(pt) => result = Some(Ok((s, pt))),
                    Err(e) => {
                        // A first-flight message with an unknown key may start
                        // a new session (the peer lost its state, or both
                        // started at once).
                        let fresh = env
                            .header
                            .init_ek
                            .filter(|ek| ek != existing.origin_ek() && !st.seen_eks.contains(ek));
                        match fresh {
                            Some(ek) => {
                                if existing.is_initiator()
                                    && existing.awaiting_first_reply()
                                    && existing.origin_ek() < &ek
                                {
                                    // We both started; ours wins. Ask the
                                    // peer to try again after it has ours.
                                    return Step::Done(AckStatus::Busy);
                                }
                                replaced = true;
                                new_ek = Some(ek);
                                result = Some(Session::accept(me, peer, &env));
                            }
                            None => {
                                if e == CryptoError::Replay && st.recent_env.contains(&env.id) {
                                    return Step::Done(AckStatus::Duplicate);
                                }
                                return Step::Done(AckStatus::BadRequest);
                            }
                        }
                    }
                }
            } else {
                match env.header.init_ek {
                    Some(ek) if !st.seen_eks.contains(&ek) => {
                        new_ek = Some(ek);
                        result = Some(Session::accept(me, peer, &env));
                    }
                    Some(_) => return Step::Done(AckStatus::BadRequest),
                    None => return Step::Done(AckStatus::NoSession),
                }
            }
            match result {
                Some(Ok((session, pt))) => match Record::decode(&pt) {
                    Ok(record) => Step::Open {
                        session,
                        record,
                        replaced,
                        new_ek,
                    },
                    Err(_) => Step::Done(AckStatus::BadRequest),
                },
                _ => Step::Done(AckStatus::BadRequest),
            }
        });
        let (session, record, replaced, new_ek) = match step {
            Step::Done(s) => return plain(s),
            Step::Open {
                session,
                record,
                replaced,
                new_ek,
            } => (session, record, replaced, new_ek),
        };
        let message = match record {
            Record::Text(m) => m,
            Record::Read(rc) => {
                // A receipt: no history record, no sequence number, and never
                // an answer of its own. It is applied only when receipts are
                // on here; otherwise it is acknowledged and forgotten.
                let enabled = self.receipts_enabled(peer);
                let mut applied = false;
                self.store.with_peer(peer, |st| {
                    st.session = Some(session);
                    if let Some(ek) = new_ek {
                        st.remember_ek(ek);
                    }
                    st.remember_envelope(env.id);
                    // Only numbers this side really sent can be read.
                    if enabled && rc.up_to_seq <= st.send_seq && rc.up_to_seq > st.read_up_to {
                        st.read_up_to = rc.up_to_seq;
                        applied = true;
                    }
                });
                if self.store.flush_peer(peer).is_err() {
                    return plain(AckStatus::Failed);
                }
                if replaced {
                    self.void_sealed(peer);
                }
                if applied {
                    self.push_event(
                        *peer,
                        EventKind::Read,
                        StoredMessage {
                            ord: 0,
                            outgoing: true,
                            id: rc.id,
                            seq: rc.up_to_seq,
                            sent_ms: 0,
                            at_ms: now,
                            state: MsgState::Read,
                            reason: None,
                            text: String::new(),
                        },
                    );
                }
                return AcceptOutcome {
                    status: AckStatus::Stored,
                    session_replaced: replaced,
                };
            }
        };

        // Step 2: a number already applied is a duplicate; the key it used is
        // gone either way, so the session moves on.
        let is_new = self.store.peek_peer(peer, |st| st.is_new_seq(message.seq));
        let too_big = message.text.len() > max_text;
        let mut stored: Option<StoredMessage> = None;
        if is_new && !too_big {
            let nm = NewMessage {
                outgoing: false,
                id: message.id,
                seq: message.seq,
                sent_ms: message.sent_ms,
                at_ms: now,
                state: MsgState::Received,
                reason: None,
                text: message.text.clone(),
            };
            match self.store.record(peer, nm, true) {
                Ok(ord) => {
                    stored = Some(StoredMessage {
                        ord,
                        outgoing: false,
                        id: message.id,
                        seq: message.seq,
                        sent_ms: message.sent_ms,
                        at_ms: now,
                        state: MsgState::Received,
                        reason: None,
                        text: message.text.clone(),
                    })
                }
                Err(_) => return plain(AckStatus::Failed),
            }
        }

        // Step 3: commit.
        self.store.with_peer(peer, |st| {
            st.session = Some(session);
            if let Some(ek) = new_ek {
                st.remember_ek(ek);
            }
            st.mark_seq(message.seq);
            st.remember_envelope(env.id);
        });
        if self.store.flush_peer(peer).is_err() {
            return plain(AckStatus::Failed);
        }
        if replaced {
            self.void_sealed(peer);
        }
        let status = if too_big {
            AckStatus::TooBig
        } else if stored.is_some() {
            AckStatus::Stored
        } else {
            AckStatus::Duplicate
        };
        if let Some(m) = stored {
            self.push_event(*peer, EventKind::Received, m);
        }
        AcceptOutcome {
            status,
            session_replaced: replaced,
        }
    }
}

impl ChatCore {
    /// Put a message that never left the outbox (expired while the program
    /// was off) into the history as failed.
    pub fn record_unsent(&self, e: &OutEntry, reason: &str, now: u64) {
        let nm = Self::stored_from(e, MsgState::Failed, Some(reason.to_owned()), now);
        let _ = self.store.record(&e.peer, nm, false);
    }
}
