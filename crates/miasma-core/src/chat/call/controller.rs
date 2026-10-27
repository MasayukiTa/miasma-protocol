//! Dormant call controller core (PR5a).
//!
//! This module turns the pure per-call state machine ([`super::state`]) into a
//! driver that a daemon can own: it maps received signalling records
//! ([`super::signal::Record`]) to machine events, maps the machine's effects
//! back to records, and keeps the small amount of per-call context the machine
//! does not hold (the call nonce, the offer timestamps, the pending incoming
//! offer and a bounded notice queue).
//!
//! It is pure and testable: every side effect (clock, id/nonce generation,
//! sending, contact checks) is reached through an injected [`CallPorts`], so a
//! test can supply deterministic ids and record the bytes that would be sent.
//! It performs no real I/O itself and does not touch the daemon. The daemon
//! wiring and the IPC surface are a later PR; this file is dormant.
//!
//! Privacy (design-call-security-v7f.md chapter 3, §6): no secret, key, nonce,
//! call id or peer id ever reaches a log, an error string or a `Debug` output.
//! The context type that holds a nonce and an offer hash deliberately does not
//! derive `Debug`; types that hold a peer id or call id either omit `Debug` or
//! print a fixed string. Hostile input never panics: the controller only feeds
//! the machine, which is total over state x event, and decodes with the strict
//! codec, dropping anything that does not decode.

use std::collections::VecDeque;

use zeroize::Zeroize;

use super::caps::Capabilities;
use super::inbound::CallInbound;
use super::signal::{self, reason, Record, CALL_ID_LEN, CALL_NONCE_LEN, OFFER_HASH_LEN};
use super::state::{
    CallId, CallMachine, Control, Effect, Event, Notice, Offer, PeerId, Reason, State,
};

/// Capacity of the user-facing notice queue. Oldest notices are dropped and a
/// `gap` flag is raised when more than this many pile up unread.
pub const NOTICE_QUEUE_CAP: usize = 64;

/// Offer time-to-live in milliseconds (45 s): an offer still in `Calling` or
/// `Ringing` this long after it was created feeds [`Event::Timeout`]. Kept in
/// step with [`super::state::OFFER_TTL_MS`] and the signalling default.
pub const OFFER_TTL_MS: u64 = 45_000;

/// Outcome of one send attempt. The daemon later adapts
/// [`super::immediate::ChatService::send_call_control`] to return this; the
/// controller only needs to know whether the record left the machine.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SendResult {
    Sent,
    Failed,
}

/// The injected I/O surface. Pure so tests can supply deterministic ids and
/// capture sent bytes. No method returns or logs a secret.
pub trait CallPorts {
    /// The current time in milliseconds.
    fn now_ms(&self) -> u64;
    /// A fresh call id. Tests may inject a deterministic counter; production
    /// draws from the OS random source via [`signal::new_call_id`].
    fn new_call_id(&mut self) -> [u8; CALL_ID_LEN];
    /// A fresh call nonce. Tests may inject a deterministic counter; production
    /// draws from the OS random source via [`signal::new_call_nonce`].
    fn new_call_nonce(&mut self) -> [u8; CALL_NONCE_LEN];
    /// Send one encoded signalling record to `peer`. The daemon wires this to
    /// `send_call_control`; the controller only reads the [`SendResult`].
    fn send(&mut self, peer: &[u8; 32], encoded: Vec<u8>) -> SendResult;
    /// Whether sending to `peer` is allowed (a known, send-allowed contact).
    fn is_contact_allowed(&self, peer: &[u8; 32]) -> bool;
}

/// A user-facing notice with no call id or peer id, safe to render or log.
/// Mirrors [`Notice`] one-to-one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CallNotice {
    IncomingRinging,
    Rejected,
    PeerBusy,
    NoAnswer,
    Connected,
    CallEnded,
    EstablishmentFailed,
    ClearIncoming,
    /// A send of an outgoing control record failed; the call returned to idle.
    SendFailed,
}

impl CallNotice {
    fn from_state(n: Notice) -> Self {
        match n {
            Notice::IncomingRinging => CallNotice::IncomingRinging,
            Notice::Rejected => CallNotice::Rejected,
            Notice::PeerBusy => CallNotice::PeerBusy,
            Notice::NoAnswer => CallNotice::NoAnswer,
            Notice::Connected => CallNotice::Connected,
            Notice::CallEnded => CallNotice::CallEnded,
            Notice::EstablishmentFailed => CallNotice::EstablishmentFailed,
            Notice::ClearIncoming => CallNotice::ClearIncoming,
        }
    }
}

/// The signalling-level state reported to a UI. `Connected` here means the
/// SIGNALLING is connected (an answer was exchanged), NOT that media flows:
/// media is a later PR and no media key exists yet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CallState {
    Idle,
    Calling,
    Ringing,
    /// Signalling connected (not media).
    Connected,
}

impl CallState {
    fn from_state(s: State) -> Self {
        match s {
            State::Idle => CallState::Idle,
            State::Calling => CallState::Calling,
            State::Ringing => CallState::Ringing,
            State::Connected => CallState::Connected,
        }
    }
}

/// A snapshot for a UI. Carries no call id or peer id.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CallStatus {
    pub state: CallState,
    /// A monotonically increasing token for the current incoming offer, so a
    /// stale UI cannot approve a replacement offer with an old token.
    pub pending_token: Option<u64>,
    /// True once signalling is connected (see [`CallState::Connected`]); this is
    /// not a media indication.
    pub signalling_connected: bool,
    /// True if the notice queue dropped at least one notice (overflow).
    pub notice_gap: bool,
}

/// Context for an outgoing offer we sent (we are the caller): the nonce,
/// timestamps and the offer hash we must be able to reproduce or wipe. Holds a
/// nonce and a hash, so it must never be printed: no `Debug` is derived and a
/// fixed-string `Debug` is provided instead.
struct OutgoingContext {
    peer: [u8; 32],
    call_id: [u8; CALL_ID_LEN],
    call_nonce: [u8; CALL_NONCE_LEN],
    created_at_ms: u64,
    expires_at_ms: u64,
    offer_hash: [u8; OFFER_HASH_LEN],
}

impl core::fmt::Debug for OutgoingContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OutgoingContext")
    }
}

impl OutgoingContext {
    fn wipe(&mut self) {
        self.call_nonce.zeroize();
        self.offer_hash.zeroize();
        self.call_id.zeroize();
    }
}

/// Context for an incoming offer we are ringing on (we are the callee): the
/// sender, the echoed call id, the offer's nonce and its offer hash, needed to
/// answer. Same privacy rule: no derived `Debug`.
struct IncomingContext {
    peer: [u8; 32],
    call_id: [u8; CALL_ID_LEN],
    call_nonce: [u8; CALL_NONCE_LEN],
    created_at_ms: u64,
    offer_hash: [u8; OFFER_HASH_LEN],
}

impl core::fmt::Debug for IncomingContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IncomingContext")
    }
}

impl IncomingContext {
    fn wipe(&mut self) {
        self.call_nonce.zeroize();
        self.offer_hash.zeroize();
        self.call_id.zeroize();
    }
}

/// The dormant call controller: one [`CallMachine`] plus the context and notice
/// queue the machine does not own. No `Debug`: it holds call ids and nonces.
pub struct CallController {
    machine: CallMachine,
    /// The peer of the active outgoing/connected call (the dialled contact).
    active_peer: Option<[u8; 32]>,
    /// Context of an offer we sent and are waiting on (caller side).
    outgoing: Option<OutgoingContext>,
    /// Context of an offer we are ringing on (callee side).
    incoming: Option<IncomingContext>,
    /// When the current offer was created (ms), for the TTL in [`on_tick`].
    offer_created_ms: Option<u64>,
    /// Bounded notice queue; oldest dropped on overflow with `notice_gap` set.
    notices: VecDeque<CallNotice>,
    notice_gap: bool,
    /// Monotonic token for the current incoming offer.
    pending_token: Option<u64>,
    next_token: u64,
}

impl Default for CallController {
    fn default() -> Self {
        Self::new()
    }
}

impl CallController {
    /// A fresh controller in idle with an empty queue.
    pub fn new() -> Self {
        CallController {
            machine: CallMachine::new(),
            active_peer: None,
            outgoing: None,
            incoming: None,
            offer_created_ms: None,
            notices: VecDeque::new(),
            notice_gap: false,
            pending_token: None,
            next_token: 1,
        }
    }

    /// The current status snapshot for a UI.
    pub fn status(&self) -> CallStatus {
        let state = CallState::from_state(self.machine.state());
        CallStatus {
            state,
            pending_token: self.pending_token,
            signalling_connected: state == CallState::Connected,
            notice_gap: self.notice_gap,
        }
    }

    /// Pop the oldest queued notice, if any.
    pub fn next_notice(&mut self) -> Option<CallNotice> {
        self.notices.pop_front()
    }

    fn push_notice(&mut self, n: CallNotice) {
        if self.notices.len() >= NOTICE_QUEUE_CAP {
            self.notices.pop_front();
            self.notice_gap = true;
        }
        self.notices.push_back(n);
    }

    // ---- commands ----

    /// User pressed dial: generate a fresh call id and nonce, record the offer
    /// context, and drive the machine, sending the resulting offer.
    pub fn dial<P: CallPorts>(&mut self, ports: &mut P, contact_endpoint: [u8; 32]) {
        if self.machine.state() != State::Idle {
            return;
        }
        let now = ports.now_ms();
        let call_id = ports.new_call_id();
        let call_nonce = ports.new_call_nonce();
        let created_at_ms = now;
        let expires_at_ms = now.saturating_add(OFFER_TTL_MS);
        let capabilities = Capabilities::default_local().encode();
        // Compute the offer hash over the exact body we will send so it matches
        // what the peer verifies; if encoding fails (it cannot for a valid
        // record) we do not dial.
        let probe = Record::Offer {
            call_id,
            call_nonce,
            created_at_ms,
            expires_at_ms,
            capabilities: capabilities.clone(),
        };
        let offer_hash = match probe.encode() {
            Ok(body) => signal::offer_hash(&body),
            Err(_) => return,
        };
        self.active_peer = Some(contact_endpoint);
        self.outgoing = Some(OutgoingContext {
            peer: contact_endpoint,
            call_id,
            call_nonce,
            created_at_ms,
            expires_at_ms,
            offer_hash,
        });
        self.offer_created_ms = Some(created_at_ms);
        let t = self.machine.step(
            Event::UserDial {
                call_id: CallId::new(call_id),
                peer_id: PeerId(contact_endpoint),
            },
            now,
        );
        self.apply(ports, t.next, t.effects);
    }

    /// User accepted the incoming call. The token must match the current
    /// pending offer, so a stale UI cannot approve a replacement.
    pub fn accept<P: CallPorts>(&mut self, ports: &mut P, token: u64) {
        if self.pending_token != Some(token) {
            return;
        }
        let now = ports.now_ms();
        let t = self.machine.step(Event::UserAccept, now);
        self.apply(ports, t.next, t.effects);
    }

    /// User rejected the incoming call. The token must match the pending offer.
    pub fn reject<P: CallPorts>(&mut self, ports: &mut P, token: u64) {
        if self.pending_token != Some(token) {
            return;
        }
        let now = ports.now_ms();
        let t = self.machine.step(Event::UserReject, now);
        self.apply(ports, t.next, t.effects);
    }

    /// User hung up (cancel if calling, bye if connected).
    pub fn hang_up<P: CallPorts>(&mut self, ports: &mut P) {
        let now = ports.now_ms();
        let t = self.machine.step(Event::UserHangUp, now);
        self.apply(ports, t.next, t.effects);
    }

    /// An authenticated inbound signalling record arrived.
    pub fn on_inbound<P: CallPorts>(&mut self, ports: &mut P, inbound: CallInbound) {
        let CallInbound {
            peer,
            signal,
            received_at_ms,
        } = inbound;
        let Some(event) = self.map_inbound(ports, &peer, &signal, received_at_ms) else {
            return;
        };
        // If this is an offer, build its context but do NOT store it yet: only
        // an offer the machine actually rings on (a fresh IncomingRinging) may
        // replace the pending answer context. An offer that is refused with a
        // Busy, dropped, or that only loses a tie-break must not overwrite the
        // context of the call we are already ringing on.
        let offered = match &signal {
            Record::Offer {
                call_id,
                call_nonce,
                created_at_ms,
                ..
            } => signal.encode().ok().map(|body| IncomingContext {
                peer,
                call_id: *call_id,
                call_nonce: *call_nonce,
                created_at_ms: *created_at_ms,
                offer_hash: signal::offer_hash(&body),
            }),
            _ => None,
        };
        let now = ports.now_ms();
        let t = self.machine.step(event, now);
        let rings = t
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Show(Notice::IncomingRinging)));
        if rings {
            if let Some(ctx) = offered {
                if let Some(mut old) = self.incoming.replace(ctx) {
                    old.wipe();
                }
            }
        }
        self.apply(ports, t.next, t.effects);
    }

    /// A periodic tick: if an offer has been pending past its TTL while still in
    /// `Calling` or `Ringing`, feed [`Event::Timeout`].
    pub fn on_tick<P: CallPorts>(&mut self, ports: &mut P) {
        let now = ports.now_ms();
        let still_pending = matches!(self.machine.state(), State::Calling | State::Ringing);
        if !still_pending {
            return;
        }
        if let Some(created) = self.offer_created_ms {
            if now >= created.saturating_add(OFFER_TTL_MS) {
                let t = self.machine.step(Event::Timeout, now);
                self.apply(ports, t.next, t.effects);
            }
        }
    }

    // ---- inbound mapping ----

    /// Map a received record to a machine event, or `None` to drop it silently.
    ///
    /// `Offer` always maps (the machine itself decides contact/expiry/busy via
    /// the distilled [`Offer`]). Every other kind maps only if the sender is the
    /// stored active peer; otherwise it is dropped. `Ack` and `Collide` have no
    /// matching event in [`super::state`], so they are ignored here.
    fn map_inbound<P: CallPorts>(
        &self,
        ports: &P,
        peer: &[u8; 32],
        signal: &Record,
        received_at_ms: u64,
    ) -> Option<Event> {
        match signal {
            Record::Offer {
                call_id,
                expires_at_ms,
                ..
            } => {
                let from_contact = ports.is_contact_allowed(peer);
                let expired = *expires_at_ms < received_at_ms;
                let other_call_active = self.machine.state() != State::Idle;
                Some(Event::ReceivedOffer(Offer {
                    call_id: CallId::new(*call_id),
                    peer_id: PeerId(*peer),
                    from_contact,
                    expired,
                    other_call_active,
                }))
            }
            Record::Answer { call_id, .. } => self.if_active_peer(peer, || Event::ReceivedAnswer {
                call_id: CallId::new(*call_id),
            }),
            Record::Reject { call_id, .. } => self.if_active_peer(peer, || Event::ReceivedReject {
                call_id: CallId::new(*call_id),
            }),
            Record::Busy { call_id, .. } => self.if_active_peer(peer, || Event::ReceivedBusy {
                call_id: CallId::new(*call_id),
            }),
            Record::Cancel { call_id, .. } => self.if_active_peer(peer, || Event::ReceivedCancel {
                call_id: CallId::new(*call_id),
            }),
            Record::Bye { call_id, .. } => self.if_active_peer(peer, || Event::ReceivedHangUp {
                call_id: CallId::new(*call_id),
            }),
            // No state event carries an Ack or a Collide: ignore both.
            Record::Ack { .. } | Record::Collide { .. } => None,
        }
    }

    fn if_active_peer(&self, peer: &[u8; 32], make: impl FnOnce() -> Event) -> Option<Event> {
        match self.active_peer {
            Some(active) if &active == peer => Some(make()),
            _ => None,
        }
    }

    // ---- effect application ----

    fn apply<P: CallPorts>(&mut self, ports: &mut P, next: State, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::Send {
                    control,
                    call_id,
                    reason,
                } => {
                    self.do_send(ports, control, call_id, reason);
                }
                Effect::Collide {
                    call_id,
                    peer_call_id,
                } => {
                    self.do_collide(ports, call_id, peer_call_id);
                }
                Effect::Show(n) => self.push_notice(CallNotice::from_state(n)),
                Effect::ZeroizeKeys => self.wipe_contexts(),
                Effect::ReplaceSasInput { .. } => {
                    // Media keys do not exist yet; the only SAS input the
                    // controller holds is the offer context it is abandoning.
                    // Clear it so no stale nonce/hash lingers; the adopted
                    // offer's context is already stored in `incoming`.
                    if let Some(mut c) = self.outgoing.take() {
                        c.wipe();
                    }
                }
            }
        }
        self.sync_pending(next);
        if next == State::Idle {
            self.active_peer = None;
            self.offer_created_ms = None;
            self.wipe_contexts();
        }
    }

    /// Keep the pending token in step with the machine state: a token exists
    /// exactly while an incoming offer is ringing.
    fn sync_pending(&mut self, next: State) {
        match next {
            State::Ringing => {
                if self.pending_token.is_none() {
                    let token = self.next_token;
                    self.next_token = self.next_token.saturating_add(1);
                    self.pending_token = Some(token);
                }
                // The callee's peer is the offerer, recorded in `incoming`.
                if self.active_peer.is_none() {
                    let offerer = self.incoming.as_ref().map(|c| c.peer);
                    if let Some(peer) = offerer {
                        self.active_peer = Some(peer);
                    }
                }
            }
            _ => {
                self.pending_token = None;
            }
        }
    }

    fn do_send<P: CallPorts>(
        &mut self,
        ports: &mut P,
        control: Control,
        call_id: CallId,
        reason: Option<Reason>,
    ) {
        let Some((peer, record)) = self.build_record(ports, control, call_id, reason) else {
            return;
        };
        let Ok(encoded) = record.encode() else {
            return;
        };
        if ports.send(&peer, encoded) == SendResult::Failed {
            self.on_send_failed(ports);
        }
    }

    /// Build the record and its destination for a [`Control`]. Returns `None`
    /// when a required context is missing (treated as nothing to send).
    fn build_record<P: CallPorts>(
        &self,
        ports: &P,
        control: Control,
        call_id: CallId,
        reason: Option<Reason>,
    ) -> Option<([u8; 32], Record)> {
        let id = call_id.0;
        match control {
            Control::Offer => {
                let c = self.outgoing.as_ref()?;
                Some((
                    c.peer,
                    Record::Offer {
                        call_id: c.call_id,
                        call_nonce: c.call_nonce,
                        created_at_ms: c.created_at_ms,
                        expires_at_ms: c.expires_at_ms,
                        capabilities: Capabilities::default_local().encode(),
                    },
                ))
            }
            Control::Answer => {
                let c = self.incoming.as_ref()?;
                Some((
                    c.peer,
                    Record::Answer {
                        call_id: c.call_id,
                        call_nonce: c.call_nonce,
                        created_at_ms: ports.now_ms(),
                        capabilities: Capabilities::default_local().encode(),
                    },
                ))
            }
            Control::Reject => {
                let peer = self.reply_peer()?;
                Some((
                    peer,
                    Record::Reject {
                        call_id: id,
                        created_at_ms: ports.now_ms(),
                        reason: wire_reason(reason),
                    },
                ))
            }
            Control::Busy => {
                // Busy answers the incoming offer's sender, NOT the active peer.
                // The machine emits Busy with the offer's call id; find the
                // sender by matching that id against the pending incoming
                // context, else fall back to the active peer.
                let peer = self.busy_peer(&id)?;
                Some((
                    peer,
                    Record::Busy {
                        call_id: id,
                        created_at_ms: ports.now_ms(),
                        reason: wire_reason(reason),
                    },
                ))
            }
            Control::Cancel => {
                let peer = self.reply_peer()?;
                Some((
                    peer,
                    Record::Cancel {
                        call_id: id,
                        created_at_ms: ports.now_ms(),
                        reason: wire_reason(reason),
                    },
                ))
            }
            Control::Bye => {
                let peer = self.reply_peer()?;
                Some((
                    peer,
                    Record::Bye {
                        call_id: id,
                        created_at_ms: ports.now_ms(),
                    },
                ))
            }
            // A bare Collide control (no echoed peer id) is produced only via
            // Effect::Collide, handled in do_collide; nothing to build here.
            Control::Collide => None,
        }
    }

    /// The peer to reply to for records bound to our own active call.
    fn reply_peer(&self) -> Option<[u8; 32]> {
        self.active_peer
    }

    /// The sender of the incoming offer a Busy answers. The machine's Busy
    /// carries the offer's call id; if it matches the stored incoming context
    /// use that sender, otherwise the active peer (a busy raised while calling).
    fn busy_peer(&self, offer_id: &[u8; CALL_ID_LEN]) -> Option<[u8; 32]> {
        if let Some(c) = &self.incoming {
            if &c.call_id == offer_id {
                return Some(c.peer);
            }
        }
        self.active_peer
    }

    fn do_collide<P: CallPorts>(&mut self, ports: &mut P, call_id: CallId, peer_call_id: CallId) {
        let Some(peer) = self.active_peer else {
            return;
        };
        let record = Record::Collide {
            call_id: call_id.0,
            peer_call_id: peer_call_id.0,
            created_at_ms: ports.now_ms(),
        };
        let Ok(encoded) = record.encode() else {
            return;
        };
        if ports.send(&peer, encoded) == SendResult::Failed {
            self.on_send_failed(ports);
        }
    }

    /// A failed send must be visible and return the machine to idle. We feed the
    /// event that cleanly ends the current state: `UserHangUp` while calling or
    /// connected (cancel/bye, already failed so the follow-up send is harmless),
    /// `UserReject` while ringing, and nothing while already idle. Then a
    /// `SendFailed` notice is queued.
    fn on_send_failed<P: CallPorts>(&mut self, ports: &mut P) {
        let now = ports.now_ms();
        let event = match self.machine.state() {
            State::Calling | State::Connected => Some(Event::UserHangUp),
            State::Ringing => Some(Event::UserReject),
            State::Idle => None,
        };
        if let Some(event) = event {
            let t = self.machine.step(event, now);
            // Apply only the non-send bookkeeping of the teardown: show notices
            // and wipe. Do not recurse into do_send for the teardown's own
            // control record (the channel already failed).
            for effect in t.effects {
                match effect {
                    Effect::Show(n) => self.push_notice(CallNotice::from_state(n)),
                    Effect::ZeroizeKeys => self.wipe_contexts(),
                    _ => {}
                }
            }
            self.sync_pending(t.next);
            if t.next == State::Idle {
                self.active_peer = None;
                self.offer_created_ms = None;
                self.wipe_contexts();
            }
        }
        self.push_notice(CallNotice::SendFailed);
    }

    fn wipe_contexts(&mut self) {
        if let Some(mut c) = self.outgoing.take() {
            c.wipe();
        }
        if let Some(mut c) = self.incoming.take() {
            c.wipe();
        }
    }
}

impl core::fmt::Debug for CallController {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CallController")
    }
}

/// Map a state [`Reason`] to a signalling wire reason byte. Every variant is
/// mapped explicitly; the choice for each is documented inline. The gate-
/// derived codes (`PQC_*`, `GATE_UNDECIDED`, `NOT_CONTACT`) are produced by
/// other layers, never by this mapping.
fn wire_reason(reason: Option<Reason>) -> u8 {
    match reason {
        // The callee declined.
        Some(Reason::Declined) => reason::DECLINED,
        // The caller withdrew the call.
        Some(Reason::Canceled) => reason::CANCELED,
        // No answer within the TTL.
        Some(Reason::Timeout) => reason::TIMEOUT,
        // Already in another call.
        Some(Reason::Busy) => reason::BUSY,
        // Lost the simultaneous-offer tie-break.
        Some(Reason::CollisionLost) => reason::COLLISION_LOST,
        // Media could not be established after approval. Signalling has no
        // dedicated code for this; reuse the generic refusal `DECLINED`.
        Some(Reason::EstablishmentFailed) => reason::DECLINED,
        // A control with no reason (should not reach a reason-carrying record);
        // default to the generic refusal so a wire byte is always valid.
        None => reason::DECLINED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic ports double. Ids and nonces come from counters (not
    /// fixed secrets): each call returns the next value, so tests stay
    /// reproducible without hard-coding any identifier. Sent records are kept
    /// for inspection.
    struct FakePorts {
        now: u64,
        id_counter: u8,
        nonce_counter: u8,
        allowed: bool,
        fail_send: bool,
        sent: Vec<([u8; 32], Vec<u8>)>,
    }

    impl FakePorts {
        fn new() -> Self {
            FakePorts {
                now: 1_000,
                id_counter: 0,
                nonce_counter: 0,
                allowed: true,
                fail_send: false,
                sent: Vec::new(),
            }
        }

        fn last(&self) -> &([u8; 32], Vec<u8>) {
            self.sent.last().expect("a record should have been sent")
        }
    }

    impl CallPorts for FakePorts {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn new_call_id(&mut self) -> [u8; CALL_ID_LEN] {
            self.id_counter = self.id_counter.wrapping_add(1);
            [self.id_counter; CALL_ID_LEN]
        }
        fn new_call_nonce(&mut self) -> [u8; CALL_NONCE_LEN] {
            self.nonce_counter = self.nonce_counter.wrapping_add(1);
            [self.nonce_counter; CALL_NONCE_LEN]
        }
        fn send(&mut self, peer: &[u8; 32], encoded: Vec<u8>) -> SendResult {
            self.sent.push((*peer, encoded));
            if self.fail_send {
                SendResult::Failed
            } else {
                SendResult::Sent
            }
        }
        fn is_contact_allowed(&self, _peer: &[u8; 32]) -> bool {
            self.allowed
        }
    }

    fn offer_record(sender_id: u8, now: u64) -> Record {
        Record::Offer {
            call_id: [sender_id; CALL_ID_LEN],
            call_nonce: [sender_id; CALL_NONCE_LEN],
            created_at_ms: now,
            expires_at_ms: now + OFFER_TTL_MS,
            capabilities: Capabilities::default_local().encode(),
        }
    }

    fn inbound(peer: [u8; 32], signal: Record, now: u64) -> CallInbound {
        CallInbound {
            peer,
            signal,
            received_at_ms: now,
        }
    }

    #[test]
    fn dial_sends_offer_to_the_right_peer_with_caps() {
        let mut ports = FakePorts::new();
        let mut c = CallController::new();
        let peer = [7u8; 32];
        c.dial(&mut ports, peer);
        assert_eq!(c.status().state, CallState::Calling);
        let (to, body) = ports.last();
        assert_eq!(*to, peer);
        let record = Record::decode(body).expect("the offer must decode");
        match record {
            Record::Offer { capabilities, .. } => {
                assert_eq!(
                    Capabilities::decode(&capabilities),
                    Ok(Capabilities::default_local())
                );
            }
            _ => panic!("dial must send an Offer"),
        }
    }

    #[test]
    fn incoming_offer_rings_and_notices() {
        let mut ports = FakePorts::new();
        let mut c = CallController::new();
        let peer = [3u8; 32];
        c.on_inbound(
            &mut ports,
            inbound(peer, offer_record(3, ports.now), ports.now),
        );
        assert_eq!(c.status().state, CallState::Ringing);
        assert!(c.status().pending_token.is_some());
        assert_eq!(c.next_notice(), Some(CallNotice::IncomingRinging));
    }

    #[test]
    fn accept_sends_answer_to_the_offerer() {
        let mut ports = FakePorts::new();
        let mut c = CallController::new();
        let peer = [3u8; 32];
        c.on_inbound(
            &mut ports,
            inbound(peer, offer_record(3, ports.now), ports.now),
        );
        let token = c.status().pending_token.unwrap();
        c.accept(&mut ports, token);
        assert_eq!(c.status().state, CallState::Connected);
        let (to, body) = ports.last();
        assert_eq!(*to, peer);
        assert!(matches!(Record::decode(body), Ok(Record::Answer { .. })));
    }

    #[test]
    fn reject_sends_reject() {
        let mut ports = FakePorts::new();
        let mut c = CallController::new();
        let peer = [3u8; 32];
        c.on_inbound(
            &mut ports,
            inbound(peer, offer_record(3, ports.now), ports.now),
        );
        let token = c.status().pending_token.unwrap();
        c.reject(&mut ports, token);
        assert_eq!(c.status().state, CallState::Idle);
        let (to, body) = ports.last();
        assert_eq!(*to, peer);
        assert!(matches!(Record::decode(body), Ok(Record::Reject { .. })));
    }

    #[test]
    fn second_offer_while_ringing_gets_busy_to_its_sender() {
        let mut ports = FakePorts::new();
        let mut c = CallController::new();
        let first = [3u8; 32];
        let second = [9u8; 32];
        c.on_inbound(
            &mut ports,
            inbound(first, offer_record(3, ports.now), ports.now),
        );
        assert_eq!(c.status().state, CallState::Ringing);
        c.on_inbound(
            &mut ports,
            inbound(second, offer_record(9, ports.now), ports.now),
        );
        // Still ringing on the first; a Busy went to the second sender.
        assert_eq!(c.status().state, CallState::Ringing);
        let (to, body) = ports.last();
        assert_eq!(*to, second);
        assert!(matches!(Record::decode(body), Ok(Record::Busy { .. })));
    }

    #[test]
    fn answer_from_a_stranger_is_ignored() {
        let mut ports = FakePorts::new();
        let mut c = CallController::new();
        let peer = [7u8; 32];
        c.dial(&mut ports, peer);
        let sent_before = ports.sent.len();
        let stranger = [8u8; 32];
        let ours = match &c.outgoing {
            Some(o) => o.call_id,
            None => panic!("calling must hold an outgoing context"),
        };
        c.on_inbound(
            &mut ports,
            inbound(
                stranger,
                Record::Answer {
                    call_id: ours,
                    call_nonce: [0; CALL_NONCE_LEN],
                    created_at_ms: ports.now,
                    capabilities: Capabilities::default_local().encode(),
                },
                ports.now,
            ),
        );
        assert_eq!(c.status().state, CallState::Calling);
        assert_eq!(ports.sent.len(), sent_before);
    }

    #[test]
    fn stale_token_cannot_accept_a_replacement_offer() {
        let mut ports = FakePorts::new();
        let mut c = CallController::new();
        let peer = [3u8; 32];
        c.on_inbound(
            &mut ports,
            inbound(peer, offer_record(3, ports.now), ports.now),
        );
        let stale = c.status().pending_token.unwrap();
        // The offer times out and a replacement arrives, minting a new token.
        ports.now += OFFER_TTL_MS + 1;
        c.on_tick(&mut ports);
        assert_eq!(c.status().state, CallState::Idle);
        c.on_inbound(
            &mut ports,
            inbound(peer, offer_record(4, ports.now), ports.now),
        );
        let fresh = c.status().pending_token.unwrap();
        assert_ne!(stale, fresh);
        // Accepting with the stale token must do nothing.
        c.accept(&mut ports, stale);
        assert_eq!(c.status().state, CallState::Ringing);
        // The fresh token works.
        c.accept(&mut ports, fresh);
        assert_eq!(c.status().state, CallState::Connected);
    }

    #[test]
    fn offer_ttl_timeout_returns_to_idle() {
        let mut ports = FakePorts::new();
        let mut c = CallController::new();
        let peer = [7u8; 32];
        c.dial(&mut ports, peer);
        ports.now += OFFER_TTL_MS + 1;
        c.on_tick(&mut ports);
        assert_eq!(c.status().state, CallState::Idle);
        // A cancel(timeout) went out.
        let (_, body) = ports.last();
        assert!(matches!(Record::decode(body), Ok(Record::Cancel { .. })));
    }

    #[test]
    fn send_failure_sets_sendfailed_and_idle() {
        let mut ports = FakePorts::new();
        ports.fail_send = true;
        let mut c = CallController::new();
        let peer = [7u8; 32];
        c.dial(&mut ports, peer);
        // The offer send failed, so the controller tore down to idle.
        assert_eq!(c.status().state, CallState::Idle);
        let mut saw_send_failed = false;
        while let Some(n) = c.next_notice() {
            if n == CallNotice::SendFailed {
                saw_send_failed = true;
            }
        }
        assert!(saw_send_failed, "a SendFailed notice must be queued");
    }

    #[test]
    fn notice_queue_overflow_sets_gap() {
        let mut c = CallController::new();
        for _ in 0..(NOTICE_QUEUE_CAP + 5) {
            c.push_notice(CallNotice::Connected);
        }
        assert!(c.status().notice_gap);
        assert_eq!(c.notices.len(), NOTICE_QUEUE_CAP);
    }

    #[test]
    fn wire_reason_maps_every_variant() {
        assert_eq!(wire_reason(Some(Reason::Declined)), reason::DECLINED);
        assert_eq!(wire_reason(Some(Reason::Canceled)), reason::CANCELED);
        assert_eq!(wire_reason(Some(Reason::Timeout)), reason::TIMEOUT);
        assert_eq!(wire_reason(Some(Reason::Busy)), reason::BUSY);
        assert_eq!(
            wire_reason(Some(Reason::CollisionLost)),
            reason::COLLISION_LOST
        );
        assert_eq!(
            wire_reason(Some(Reason::EstablishmentFailed)),
            reason::DECLINED
        );
        assert_eq!(wire_reason(None), reason::DECLINED);
        // Every mapped byte is a known reason code.
        for r in [
            Reason::Declined,
            Reason::Canceled,
            Reason::Timeout,
            Reason::Busy,
            Reason::CollisionLost,
            Reason::EstablishmentFailed,
        ] {
            assert!(reason::is_known(wire_reason(Some(r))));
        }
    }

    /// No panic on every record kind fed in every controller state. A sample of
    /// each kind is fed into a controller driven into each state; the only
    /// requirement is that nothing panics and the controller stays responsive.
    #[test]
    fn no_panic_on_every_record_in_every_state() {
        let now = 1_000u64;
        let peer = [5u8; 32];
        let kinds: Vec<Record> = vec![
            offer_record(5, now),
            Record::Answer {
                call_id: [5; CALL_ID_LEN],
                call_nonce: [5; CALL_NONCE_LEN],
                created_at_ms: now,
                capabilities: Capabilities::default_local().encode(),
            },
            Record::Reject {
                call_id: [5; CALL_ID_LEN],
                created_at_ms: now,
                reason: reason::DECLINED,
            },
            Record::Busy {
                call_id: [5; CALL_ID_LEN],
                created_at_ms: now,
                reason: reason::BUSY,
            },
            Record::Cancel {
                call_id: [5; CALL_ID_LEN],
                created_at_ms: now,
                reason: reason::CANCELED,
            },
            Record::Bye {
                call_id: [5; CALL_ID_LEN],
                created_at_ms: now,
            },
            Record::Ack {
                call_id: [5; CALL_ID_LEN],
                acked_kind: 0x30,
            },
            Record::Collide {
                call_id: [5; CALL_ID_LEN],
                peer_call_id: [6; CALL_ID_LEN],
                created_at_ms: now,
            },
        ];

        // Build a fresh controller in each of the four states and feed each
        // record kind into it. `build_state` returns the controller and ports.
        for target in [
            CallState::Idle,
            CallState::Calling,
            CallState::Ringing,
            CallState::Connected,
        ] {
            for k in &kinds {
                let (mut c, mut ports) = build_state(target, peer);
                // Clone the record by re-encoding/decoding so the loop owns one.
                let body = k.encode().unwrap();
                let rec = Record::decode(&body).unwrap();
                c.on_inbound(&mut ports, inbound(peer, rec, ports.now));
                // Still responsive: status does not panic.
                let _ = c.status();
            }
        }
    }

    /// Drive a fresh controller into `target` with `peer` as the counterparty.
    fn build_state(target: CallState, peer: [u8; 32]) -> (CallController, FakePorts) {
        let mut ports = FakePorts::new();
        let mut c = CallController::new();
        match target {
            CallState::Idle => {}
            CallState::Calling => {
                c.dial(&mut ports, peer);
            }
            CallState::Ringing => {
                c.on_inbound(
                    &mut ports,
                    inbound(peer, offer_record(3, ports.now), ports.now),
                );
            }
            CallState::Connected => {
                c.dial(&mut ports, peer);
                let ours = c.outgoing.as_ref().unwrap().call_id;
                c.on_inbound(
                    &mut ports,
                    inbound(
                        peer,
                        Record::Answer {
                            call_id: ours,
                            call_nonce: [0; CALL_NONCE_LEN],
                            created_at_ms: ports.now,
                            capabilities: Capabilities::default_local().encode(),
                        },
                        ports.now,
                    ),
                );
            }
        }
        (c, ports)
    }
}
