//! Call controller ports, user-facing notice queue and the incoming-call
//! approval token (PR5a1).
//!
//! This module sits above the pure [`state::CallMachine`] and owns the small
//! amount of host-facing plumbing the machine deliberately avoids: a [`CallPorts`]
//! trait for the injected clock and contact check, a bounded [`NoticeQueue`] that
//! buffers user-facing notices for a UI to drain, and a per-incoming-call
//! approval token so a stale user interface cannot approve a replacement call.
//!
//! Inbound records, user commands and timeouts drive the machine; an injected
//! sender carries encoded control records to the host transport.
//!
//! Privacy: anything that holds a call id or a peer id must not derive `Debug`
//! (a call id is secret-adjacent, see [`state`]). [`CallNotice`], [`CallStatus`]
//! and the peer field therefore get a hand-written `Debug` that prints a fixed
//! string only.

use std::collections::VecDeque;

use super::caps::{self, Capabilities};
use super::inbound::CallInbound;
use super::signal::{self, Record};
use super::state::{
    CallId, CallMachine, Control, Effect, Event, Notice, Offer, PeerId, Reason, State, OFFER_TTL_MS,
};

pub trait CallSender {
    fn send(&mut self, peer: &[u8; 32], encoded: Vec<u8>) -> bool;
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CallError {
    NotAllowed,
    Busy,
    NotReady,
    Refused,
}
impl core::fmt::Debug for CallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CallError")
    }
}
pub struct SendTicket {
    effect: Effect,
}

struct PendingSend {
    peer: [u8; 32],
    effect: Effect,
}
struct OfferContext {
    call_id: CallId,
    nonce: [u8; 16],
}

fn wire_reason(reason: Option<Reason>) -> u8 {
    match reason {
        Some(Reason::Declined) => signal::reason::DECLINED, // Direct equivalent.
        Some(Reason::Canceled) => signal::reason::CANCELED, // Direct equivalent.
        Some(Reason::Timeout) => signal::reason::TIMEOUT,   // Direct equivalent.
        Some(Reason::Busy) => signal::reason::BUSY,         // Direct equivalent.
        Some(Reason::CollisionLost) => signal::reason::COLLISION_LOST, // Direct equivalent.
        Some(Reason::EstablishmentFailed) => signal::reason::DECLINED, // No corresponding wire code.
        None => signal::reason::DECLINED,                              // Generic refusal.
    }
}

/// Host services the controller needs but does not own: the clock and the
/// contact check. Injected so the controller stays testable and performs no I/O
/// itself.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MediaGate {
    Ready,
    Pending,
    Refused,
}

pub trait CallPorts {
    /// Current time in milliseconds on the host clock.
    fn now_ms(&self) -> u64;
    /// Whether `peer` (a 32-byte identity) is a known, allowed contact.
    fn is_contact_allowed(&self, peer: &[u8; 32]) -> bool;
    fn media_gate(&self, peer: &[u8; 32]) -> MediaGate;
}

struct OfferPeer {
    peer: [u8; 32],
    times: VecDeque<u64>,
}

struct OfferLimiter {
    peers: VecDeque<OfferPeer>,
    total: VecDeque<u64>,
}

impl OfferLimiter {
    fn new() -> Self {
        Self {
            peers: VecDeque::new(),
            total: VecDeque::new(),
        }
    }

    fn allow(&mut self, peer: [u8; 32], now: u64) -> bool {
        // A backwards clock retains timestamps, failing closed until time catches up.
        self.total.retain(|t| now < *t || now - *t < 60_000);
        for entry in &mut self.peers {
            entry.times.retain(|t| now < *t || now - *t < 60_000);
        }
        let index = self.peers.iter().position(|entry| entry.peer == peer);
        if self.total.len() >= 10 || index.map_or(false, |i| self.peers[i].times.len() >= 3) {
            return false;
        }
        let mut entry = match index {
            Some(i) => match self.peers.remove(i) {
                Some(entry) => entry,
                None => return false,
            },
            None => {
                if self.peers.len() == 32 {
                    self.peers.pop_front();
                }
                OfferPeer {
                    peer,
                    times: VecDeque::new(),
                }
            }
        };
        entry.times.push_back(now);
        self.peers.push_back(entry);
        self.total.push_back(now);
        true
    }
}

#[cfg(test)]
mod inbound_tests {
    use super::super::signal::{new_call_id, new_call_nonce, Kind};
    use super::super::state::{Control, Reason};
    use super::*;

    struct Ports {
        now: u64,
        allowed: bool,
        gate: MediaGate,
    }
    impl CallPorts for Ports {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn is_contact_allowed(&self, _: &[u8; 32]) -> bool {
            self.allowed
        }
        fn media_gate(&self, _: &[u8; 32]) -> MediaGate {
            self.gate
        }
    }
    fn controller() -> CallController<Ports> {
        CallController::new(Ports {
            now: 1000,
            allowed: true,
            gate: MediaGate::Ready,
        })
    }
    fn offer(id: [u8; 16], expires: u64) -> Record {
        Record::Offer {
            call_id: id,
            call_nonce: new_call_nonce(),
            created_at_ms: 0,
            expires_at_ms: expires,
            capabilities: vec![],
        }
    }
    fn inbound(peer: [u8; 32], signal: Record) -> CallInbound {
        CallInbound {
            peer,
            signal,
            received_at_ms: 0,
        }
    }
    fn answer(id: [u8; 16]) -> Record {
        Record::Answer {
            call_id: id,
            call_nonce: new_call_nonce(),
            created_at_ms: 0,
            capabilities: Capabilities::default_local().encode(),
        }
    }

    #[test]
    fn media_gate_controls_offers() {
        for (gate, error) in [
            (MediaGate::Pending, CallError::NotReady),
            (MediaGate::Refused, CallError::Refused),
        ] {
            let mut c = controller();
            c.ports.gate = gate;
            assert_eq!(c.dial([1; 32]), Err(error));
            assert!(c.take_sends().is_empty());
            c.on_inbound(inbound([1; 32], offer([1; 16], 2000)));
            assert_eq!(c.status().state, State::Idle);
            assert!(c.take_notices().0.is_empty());
            assert_eq!(c.dropped_offers(), 0);
        }
        let mut c = controller();
        assert_eq!(c.dial([1; 32]), Ok(()));
        assert!(matches!(
            Record::decode(&c.drain_encoded()[0].1),
            Ok(Record::Offer { .. })
        ));
    }

    #[test]
    fn offer_limits_are_bounded() {
        let mut c = controller();
        for _ in 0..4 {
            c.on_inbound(inbound([1; 32], offer([1; 16], 100_000)));
        }
        assert_eq!(c.dropped_offers(), 1);
        c.ports.now += 60_000;
        c.on_inbound(inbound([1; 32], offer([1; 16], 100_000)));
        assert_eq!(c.dropped_offers(), 1);

        let mut limiter = OfferLimiter::new();
        for peer in 0..10 {
            assert!(limiter.allow([peer; 32], 0));
        }
        assert!(!limiter.allow([10; 32], 0));
        for peer in 10..50 {
            assert!(limiter.allow([peer; 32], u64::from(peer) * 60_000));
        }
        assert_eq!(limiter.peers.len(), 32);
    }

    struct Sender {
        accepted: bool,
        records: Vec<([u8; 32], Vec<u8>)>,
    }
    impl CallSender for Sender {
        fn send(&mut self, peer: &[u8; 32], encoded: Vec<u8>) -> bool {
            self.records.push((*peer, encoded));
            self.accepted
        }
    }

    #[test]
    fn commands_and_sends() {
        let peer = [1; 32];
        let mut c = controller();
        c.ports.allowed = false;
        assert_eq!(c.dial(peer), Err(CallError::NotAllowed));
        c.ports.allowed = true;
        assert_eq!(c.dial(peer), Ok(()));
        assert_eq!(c.dial(peer), Err(CallError::Busy));
        let mut sender = Sender {
            accepted: true,
            records: Vec::new(),
        };
        c.flush_sends(&mut sender);
        assert!(sender.records[0].0 == peer);
        match Record::decode(&sender.records[0].1) {
            Ok(Record::Offer { capabilities, .. }) => {
                assert!(Capabilities::decode(&capabilities).is_ok())
            }
            _ => panic!("expected offer"),
        }
        let mut c = controller();
        c.on_inbound(inbound(peer, offer(new_call_id(), 2000)));
        let token = c.status().pending_token.unwrap();
        assert!(!c.accept(token.wrapping_add(1)));
        c.on_inbound(inbound([2; 32], offer(new_call_id(), 2000)));
        assert!(c.accept(token));
        let mut sender = Sender {
            accepted: true,
            records: Vec::new(),
        };
        c.flush_sends(&mut sender);
        assert!(sender.records[0].0 == [2; 32]);
        assert!(matches!(
            Record::decode(&sender.records[0].1),
            Ok(Record::Busy { .. })
        ));
        assert!(sender.records[1].0 == peer);
        assert!(matches!(
            Record::decode(&sender.records[1].1),
            Ok(Record::Answer { .. })
        ));
        let mut c = controller();
        c.on_inbound(inbound(peer, offer(new_call_id(), 2000)));
        assert!(c.reject(c.status().pending_token.unwrap()));
        let mut sender = Sender {
            accepted: true,
            records: Vec::new(),
        };
        c.flush_sends(&mut sender);
        assert!(matches!(
            Record::decode(&sender.records[0].1),
            Ok(Record::Reject { .. })
        ));
    }

    #[test]
    fn failure_and_incompatible_answer() {
        let peer = [1; 32];
        let mut c = controller();
        assert!(c.dial(peer).is_ok());
        let mut sender = Sender {
            accepted: false,
            records: Vec::new(),
        };
        c.flush_sends(&mut sender);
        assert_eq!(c.status().state, State::Idle);
        assert!(c.take_notices().0.contains(&CallNotice::SendFailed));
        let mut c = controller();
        assert!(c.dial(peer).is_ok());
        let sends = c.take_sends();
        let id = match sends[0].effect {
            Effect::Send { call_id, .. } => call_id.0,
            _ => panic!("expected send"),
        };
        c.on_inbound(inbound(
            peer,
            Record::Answer {
                call_id: id,
                call_nonce: new_call_nonce(),
                created_at_ms: 0,
                capabilities: vec![1, 0, 0, 0],
            },
        ));
        assert_eq!(c.status().state, State::Idle);
        let mut sender = Sender {
            accepted: true,
            records: Vec::new(),
        };
        c.flush_sends(&mut sender);
        assert!(matches!(
            Record::decode(&sender.records[0].1),
            Ok(Record::Cancel {
                reason: signal::reason::DECLINED,
                ..
            })
        ));
    }

    #[test]
    fn reason_mapping_and_commands_in_each_state() {
        for (reason, expected) in [
            (Reason::Declined, signal::reason::DECLINED),
            (Reason::Canceled, signal::reason::CANCELED),
            (Reason::Timeout, signal::reason::TIMEOUT),
            (Reason::Busy, signal::reason::BUSY),
            (Reason::CollisionLost, signal::reason::COLLISION_LOST),
            (Reason::EstablishmentFailed, signal::reason::DECLINED),
        ] {
            assert_eq!(wire_reason(Some(reason)), expected);
        }
        assert_eq!(wire_reason(None), signal::reason::DECLINED);
        for state in [
            State::Idle,
            State::Calling,
            State::Ringing,
            State::Connected,
        ] {
            for command in 0..4 {
                let mut c = controller();
                let peer = [1; 32];
                if state == State::Calling || state == State::Connected {
                    assert!(c.dial(peer).is_ok());
                    if state == State::Connected {
                        let id = match c.pending_sends[0].effect {
                            Effect::Send { call_id, .. } => call_id,
                            _ => panic!("expected send"),
                        };
                        c.apply_event(Event::ReceivedAnswer { call_id: id }, 1000);
                    }
                } else if state == State::Ringing {
                    c.on_inbound(inbound(peer, offer(new_call_id(), 2000)));
                }
                assert_eq!(c.status().state, state);
                match command {
                    0 => {
                        let _ = c.dial(peer);
                    }
                    1 => {
                        let _ = c.accept(0);
                    }
                    2 => {
                        let _ = c.reject(0);
                    }
                    _ => c.hang_up(),
                }
            }
        }
    }

    #[test]
    fn offer_contact_expiry_and_busy() {
        let peer = [1; 32];
        let id = new_call_id();
        let mut c = controller();
        c.ports.allowed = false;
        c.on_inbound(inbound(peer, offer(id, 2000)));
        assert_eq!(c.status().state, State::Idle);
        c.ports.allowed = true;
        c.on_inbound(inbound(peer, offer(id, 999)));
        assert_eq!(c.status().state, State::Idle);
        c.on_inbound(inbound(peer, offer(id, 2000)));
        assert_eq!(c.status().state, State::Ringing);
        assert!(c.status().pending_token.is_some());
        assert_eq!(c.take_notices().0, vec![CallNotice::IncomingRinging]);
        let second_id = new_call_id();
        c.on_inbound(inbound([2; 32], offer(second_id, 2000)));
        let effects = c.take_effects();
        assert!(
            matches!(effects.as_slice(), [Effect::Send { control: Control::Busy, call_id, reason: Some(Reason::Busy) }] if *call_id == CallId(second_id))
        );
        assert!(c.peer == Some(peer));
    }

    #[test]
    fn answer_requires_active_peer() {
        let peer = [1; 32];
        let id = new_call_id();
        let mut c = controller();
        c.peer = Some(peer);
        c.apply_event(
            Event::UserDial {
                call_id: CallId(id),
                peer_id: PeerId(peer),
            },
            1000,
        );
        c.on_inbound(inbound([2; 32], answer(id)));
        assert_eq!(c.status().state, State::Calling);
        c.on_inbound(inbound(peer, answer(id)));
        assert_eq!(c.status().state, State::Connected);
    }

    #[test]
    fn timeout_clears_context_after_boundary() {
        let mut c = controller();
        c.on_inbound(inbound([1; 32], offer(new_call_id(), 100_000)));
        c.ports.now = 46_000;
        c.on_tick();
        assert_eq!(c.status().state, State::Ringing);
        c.ports.now += 1;
        c.on_tick();
        assert_eq!(c.status().state, State::Idle);
        assert!(c.peer.is_none());
        assert!(c.status().pending_token.is_none());
    }

    fn samples(id: [u8; 16]) -> Vec<Record> {
        vec![
            offer(id, 100_000),
            answer(id),
            Record::Reject {
                call_id: id,
                created_at_ms: 0,
                reason: 0,
            },
            Record::Busy {
                call_id: id,
                created_at_ms: 0,
                reason: 0,
            },
            Record::Cancel {
                call_id: id,
                created_at_ms: 0,
                reason: 0,
            },
            Record::Bye {
                call_id: id,
                created_at_ms: 0,
            },
            Record::Ack {
                call_id: id,
                acked_kind: Kind::Offer.byte(),
            },
            Record::Collide {
                call_id: id,
                peer_call_id: new_call_id(),
                created_at_ms: 0,
            },
        ]
    }

    #[test]
    fn every_record_in_every_state() {
        for target in [
            State::Idle,
            State::Calling,
            State::Ringing,
            State::Connected,
        ] {
            for index in 0..8 {
                let peer = [1; 32];
                let id = new_call_id();
                let mut c = controller();
                if target == State::Calling || target == State::Connected {
                    c.peer = Some(peer);
                    c.apply_event(
                        Event::UserDial {
                            call_id: CallId(id),
                            peer_id: PeerId(peer),
                        },
                        1000,
                    );
                    if target == State::Connected {
                        c.apply_event(
                            Event::ReceivedAnswer {
                                call_id: CallId(id),
                            },
                            1000,
                        );
                    }
                } else if target == State::Ringing {
                    c.on_inbound(inbound(peer, offer(id, 100_000)));
                }
                assert_eq!(c.status().state, target);
                for (i, record) in samples(id).into_iter().enumerate() {
                    if i == index {
                        c.on_inbound(inbound(peer, record));
                        break;
                    }
                }
            }
        }
    }

    #[test]
    fn effects_are_bounded_and_drop_oldest() {
        let mut c = controller();
        c.on_inbound(inbound([1; 32], offer(new_call_id(), u64::MAX)));
        let first = new_call_id();
        c.on_inbound(inbound([2; 32], offer(first, u64::MAX)));
        for _ in 0..16 {
            // Step past the offer-rate window so the limiter lets each one in.
            c.ports.now += 61_000;
            c.on_inbound(inbound([2; 32], offer(new_call_id(), u64::MAX)));
        }
        let effects = c.take_effects();
        assert_eq!(effects.len(), 16);
        assert!(!effects
            .iter()
            .any(|e| matches!(e, Effect::Send { call_id, .. } if *call_id == CallId(first))));
        assert!(c.take_effects().is_empty());
    }
}

/// A user-facing notice, mirroring [`state::Notice`] plus a [`CallNotice::SendFailed`]
/// variant for when the caller could not transmit a control message. Free of any
/// call id or peer id, but it still gets a fixed-string `Debug` so the set of
/// notices in flight is never printed verbatim.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CallNotice {
    IncomingRinging,
    Rejected,
    PeerBusy,
    NoAnswer,
    Connected,
    CallEnded,
    EstablishmentFailed,
    ClearIncoming,
    /// The caller failed to send a control message (e.g. transport down).
    SendFailed,
}

impl core::fmt::Debug for CallNotice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CallNotice")
    }
}

impl From<Notice> for CallNotice {
    fn from(n: Notice) -> Self {
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

/// Maximum notices buffered before the oldest is dropped.
const NOTICE_CAPACITY: usize = 64;

/// A bounded queue of user-facing notices. Holds at most [`NOTICE_CAPACITY`]
/// items; when full, a push drops the oldest item and raises a `gap` flag so the
/// UI learns that it missed at least one notice. [`NoticeQueue::drain`] reports
/// the gap once and then clears it.
pub struct NoticeQueue {
    items: VecDeque<CallNotice>,
    gap: bool,
}

impl Default for NoticeQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl NoticeQueue {
    /// An empty queue with no gap.
    pub fn new() -> Self {
        NoticeQueue {
            items: VecDeque::with_capacity(NOTICE_CAPACITY),
            gap: false,
        }
    }

    /// Append a notice. If the queue is at capacity, the oldest notice is
    /// dropped and the gap flag is set.
    pub fn push(&mut self, notice: CallNotice) {
        if self.items.len() >= NOTICE_CAPACITY {
            self.items.pop_front();
            self.gap = true;
        }
        self.items.push_back(notice);
    }

    /// Take all buffered notices, in order, and whether a gap occurred since the
    /// last drain. Clears both the buffer and the gap flag.
    pub fn drain(&mut self) -> (Vec<CallNotice>, bool) {
        let gap = self.gap;
        self.gap = false;
        (self.items.drain(..).collect(), gap)
    }

    /// Number of buffered notices.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// A snapshot of the controller for a UI. `signalling_connected` reflects the
/// signalling state machine reaching [`State::Connected`]; it does NOT mean that
/// media is flowing, only that signalling is connected.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CallStatus {
    /// A copy of the machine state.
    pub state: State,
    /// The outstanding incoming-call approval token, if any.
    pub pending_token: Option<u64>,
    /// True only in [`State::Connected`]. Means signalling is connected, not
    /// that media flows.
    pub signalling_connected: bool,
}

impl core::fmt::Debug for CallStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CallStatus")
    }
}

/// The host-facing controller around a [`CallMachine`]. Holds the injected
/// ports, the machine, the active peer, a bounded notice queue and the
/// incoming-call approval token state.
pub struct CallController<P: CallPorts> {
    ports: P,
    machine: CallMachine,
    // The active peer identity.
    peer: Option<[u8; 32]>,
    notices: NoticeQueue,
    pending_token: Option<u64>,
    next_token: u64,
    pending_sends: VecDeque<PendingSend>,
    offer_contexts: VecDeque<OfferContext>,
    entered_at_ms: Option<u64>,
    offer_limiter: OfferLimiter,
    dropped_offers: u64,
}

impl<P: CallPorts> CallController<P> {
    /// A fresh controller in the idle state with no pending approval.
    pub fn new(ports: P) -> Self {
        CallController {
            ports,
            machine: CallMachine::new(),
            peer: None,
            notices: NoticeQueue::new(),
            pending_token: None,
            next_token: 0,
            pending_sends: VecDeque::with_capacity(16),
            offer_contexts: VecDeque::with_capacity(32),
            entered_at_ms: None,
            offer_limiter: OfferLimiter::new(),
            dropped_offers: 0,
        }
    }

    /// Apply an authenticated inbound signalling record.
    pub fn on_inbound(&mut self, inbound: CallInbound) {
        let now = self.ports.now_ms();
        let old_state = self.machine.state();
        let peer = inbound.peer;
        let mut incoming_context = None;
        let event = match inbound.signal {
            Record::Offer {
                call_id,
                call_nonce,
                expires_at_ms,
                ..
            } => {
                let from_contact = self.ports.is_contact_allowed(&peer)
                    && self.ports.media_gate(&peer) == MediaGate::Ready;
                if from_contact && !self.offer_limiter.allow(peer, now) {
                    self.dropped_offers = self.dropped_offers.saturating_add(1);
                    return;
                }
                incoming_context = Some((CallId(call_id), call_nonce));
                Event::ReceivedOffer(Offer {
                    call_id: CallId(call_id),
                    peer_id: PeerId(peer),
                    from_contact,
                    expired: expires_at_ms < now,
                    other_call_active: old_state != State::Idle,
                })
            }
            Record::Answer {
                call_id,
                capabilities,
                ..
            } if self.peer == Some(peer) => {
                let id = CallId(call_id);
                if old_state == State::Calling && self.machine.matches_active(&id) {
                    if let Err(error) = Capabilities::decode(&capabilities)
                        .and_then(|remote| caps::negotiate(&Capabilities::default_local(), &remote))
                    {
                        // UserHangUp cancels the pending call and clears the machine.
                        self.apply_event(Event::UserHangUp, now);
                        if let Some(send) = self.pending_sends.back_mut() {
                            if let Effect::Send {
                                control: Control::Cancel,
                                reason,
                                ..
                            } = &mut send.effect
                            {
                                if error.reason() == signal::reason::DECLINED {
                                    *reason = Some(Reason::Declined);
                                }
                            }
                        }
                        return;
                    }
                }
                Event::ReceivedAnswer { call_id: id }
            }
            Record::Reject { call_id, .. } if self.peer == Some(peer) => Event::ReceivedReject {
                call_id: CallId(call_id),
            },
            Record::Busy { call_id, .. } if self.peer == Some(peer) => Event::ReceivedBusy {
                call_id: CallId(call_id),
            },
            Record::Cancel { call_id, .. } if self.peer == Some(peer) => Event::ReceivedCancel {
                call_id: CallId(call_id),
            },
            Record::Bye { call_id, .. } if self.peer == Some(peer) => Event::ReceivedHangUp {
                call_id: CallId(call_id),
            },
            // The machine has no events for Ack or inbound Collide.
            _ => return,
        };
        let is_offer = matches!(event, Event::ReceivedOffer(_));
        self.apply_event_to(event, now, if is_offer { Some(peer) } else { None });
        if is_offer && old_state != State::Ringing && self.machine.state() == State::Ringing {
            self.peer = Some(peer);
            if let Some((id, nonce)) = incoming_context {
                self.remember_offer(id, nonce);
            }
            self.begin_incoming();
        }
    }

    /// Inject the offer timeout after more than 45 seconds in Calling or Ringing.
    pub fn on_tick(&mut self) {
        let now = self.ports.now_ms();
        if matches!(self.machine.state(), State::Calling | State::Ringing)
            && self
                .entered_at_ms
                .map_or(false, |entered| now.saturating_sub(entered) > OFFER_TTL_MS)
        {
            self.apply_event(Event::Timeout, now);
        }
    }

    fn remember_offer(&mut self, call_id: CallId, nonce: [u8; 16]) {
        if self.offer_contexts.len() >= 32 {
            self.offer_contexts.pop_front();
        }
        self.offer_contexts
            .push_back(OfferContext { call_id, nonce });
    }

    pub fn dial(&mut self, peer: [u8; 32]) -> Result<(), CallError> {
        if !self.ports.is_contact_allowed(&peer) {
            return Err(CallError::NotAllowed);
        }
        if self.machine.state() != State::Idle {
            return Err(CallError::Busy);
        }
        match self.ports.media_gate(&peer) {
            MediaGate::Ready => {}
            MediaGate::Pending => return Err(CallError::NotReady),
            MediaGate::Refused => return Err(CallError::Refused),
        }
        let now = self.ports.now_ms();
        let call_id = CallId(signal::new_call_id());
        self.peer = Some(peer);
        self.remember_offer(call_id, signal::new_call_nonce());
        self.apply_event(
            Event::UserDial {
                call_id,
                peer_id: PeerId(peer),
            },
            now,
        );
        Ok(())
    }

    pub fn accept(&mut self, token: u64) -> bool {
        if !self.approve(token) {
            return false;
        }
        self.apply_event(Event::UserAccept, self.ports.now_ms());
        true
    }

    pub fn reject(&mut self, token: u64) -> bool {
        if !self.approve(token) {
            return false;
        }
        self.apply_event(Event::UserReject, self.ports.now_ms());
        true
    }

    pub fn hang_up(&mut self) {
        self.apply_event(Event::UserHangUp, self.ports.now_ms());
    }

    fn take_sends(&mut self) -> Vec<PendingSend> {
        self.pending_sends.drain(..).collect()
    }

    #[cfg(test)]
    fn take_effects(&mut self) -> Vec<Effect> {
        self.take_sends()
            .into_iter()
            .map(|send| send.effect)
            .collect()
    }

    fn encode_send(&self, effect: &Effect) -> Option<Vec<u8>> {
        let now = self.ports.now_ms();
        let record = match *effect {
            Effect::Send {
                control,
                call_id,
                reason,
            } => {
                let id = call_id.0;
                match control {
                    Control::Offer | Control::Answer => {
                        let nonce = self
                            .offer_contexts
                            .iter()
                            .rev()
                            .find(|c| c.call_id == call_id)?
                            .nonce;
                        let capabilities = Capabilities::default_local().encode();
                        if control == Control::Offer {
                            Record::Offer {
                                call_id: id,
                                call_nonce: nonce,
                                created_at_ms: now,
                                expires_at_ms: now.saturating_add(OFFER_TTL_MS),
                                capabilities,
                            }
                        } else {
                            Record::Answer {
                                call_id: id,
                                call_nonce: nonce,
                                created_at_ms: now,
                                capabilities,
                            }
                        }
                    }
                    Control::Reject => Record::Reject {
                        call_id: id,
                        created_at_ms: now,
                        reason: wire_reason(reason),
                    },
                    Control::Busy => Record::Busy {
                        call_id: id,
                        created_at_ms: now,
                        reason: wire_reason(reason),
                    },
                    Control::Cancel => Record::Cancel {
                        call_id: id,
                        created_at_ms: now,
                        reason: wire_reason(reason),
                    },
                    Control::Bye => Record::Bye {
                        call_id: id,
                        created_at_ms: now,
                    },
                    Control::Collide => return None, // A plain Send has no second call id.
                }
            }
            Effect::Collide {
                call_id,
                peer_call_id,
            } => Record::Collide {
                call_id: call_id.0,
                peer_call_id: peer_call_id.0,
                created_at_ms: now,
            },
            _ => return None,
        };
        record.encode().ok()
    }

    pub fn drain_encoded(&mut self) -> Vec<([u8; 32], Vec<u8>, SendTicket)> {
        let mut encoded = Vec::new();
        for send in self.take_sends() {
            let ticket = SendTicket {
                effect: send.effect,
            };
            if let Some(bytes) = self.encode_send(&ticket.effect) {
                encoded.push((send.peer, bytes, ticket));
            } else {
                self.report_send_result(ticket, false);
            }
        }
        encoded
    }

    pub fn report_send_result(&mut self, ticket: SendTicket, ok: bool) {
        if !ok {
            self.notices.push(CallNotice::SendFailed);
            if let Effect::Send {
                control: Control::Offer,
                call_id,
                ..
            } = ticket.effect
            {
                if self.machine.state() == State::Calling && self.machine.matches_active(&call_id) {
                    // Timeout uses the machine's existing cleanup path for an undeliverable offer.
                    self.apply_event(Event::Timeout, self.ports.now_ms());
                }
            }
        }
    }

    pub fn flush_sends(&mut self, sender: &mut dyn CallSender) {
        for (peer, bytes, ticket) in self.drain_encoded() {
            let ok = sender.send(&peer, bytes);
            self.report_send_result(ticket, ok);
        }
    }

    fn apply_event(&mut self, event: Event, now: u64) {
        self.apply_event_to(event, now, None);
    }

    fn apply_event_to(&mut self, event: Event, now: u64, offer_sender: Option<[u8; 32]>) {
        let old_state = self.machine.state();
        let transition = self.machine.step(event, now);
        if transition.next != old_state {
            self.entered_at_ms = if matches!(transition.next, State::Calling | State::Ringing) {
                Some(now)
            } else {
                None
            };
        }
        for effect in transition.effects {
            match effect {
                Effect::Show(notice) => self.notices.push(CallNotice::from(notice)),
                Effect::Send { .. } | Effect::Collide { .. } => {
                    let recipient = if matches!(
                        effect,
                        Effect::Send {
                            control: Control::Busy,
                            ..
                        }
                    ) {
                        offer_sender.or(self.peer)
                    } else {
                        self.peer
                    };
                    if let Some(peer) = recipient {
                        if self.pending_sends.len() >= 16 {
                            self.pending_sends.pop_front();
                        }
                        self.pending_sends.push_back(PendingSend { peer, effect });
                    } else {
                        self.notices.push(CallNotice::SendFailed);
                    }
                }
                Effect::ZeroizeKeys | Effect::ReplaceSasInput { .. } => {}
            }
        }
        if transition.next == State::Idle {
            self.peer = None;
            self.pending_token = None;
        }
    }

    /// A snapshot of the controller for a UI.
    pub fn status(&self) -> CallStatus {
        let state = self.machine.state();
        CallStatus {
            state,
            pending_token: self.pending_token,
            signalling_connected: state == State::Connected,
        }
    }

    pub fn dropped_offers(&self) -> u64 {
        self.dropped_offers
    }

    /// Take all buffered notices and whether a gap occurred since the last call.
    pub fn take_notices(&mut self) -> (Vec<CallNotice>, bool) {
        self.notices.drain()
    }

    /// Begin handling an incoming call by allocating a fresh approval token. The
    /// token is unique and strictly increasing; it becomes the only value
    /// [`CallController::approve`] will accept, so a stale UI holding an older
    /// token cannot approve a replacement call.
    pub fn begin_incoming(&mut self) -> u64 {
        let token = self.next_token;
        if let Some(next) = self.next_token.checked_add(1) {
            self.next_token = next;
            self.pending_token = Some(token);
        } else {
            // Exhaustion fails closed rather than reusing an approval token.
            self.pending_token = None;
        }
        token
    }

    /// Approve a pending incoming call. Returns true only when `token` equals the
    /// outstanding pending token; on success the pending token is cleared so it
    /// cannot be reused.
    pub fn approve(&mut self, token: u64) -> bool {
        if self.pending_token == Some(token) {
            self.pending_token = None;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake [`CallPorts`] with a fixed clock that allows every contact.
    struct FakePorts {
        now: u64,
    }

    impl CallPorts for FakePorts {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn is_contact_allowed(&self, _peer: &[u8; 32]) -> bool {
            true
        }
        fn media_gate(&self, _: &[u8; 32]) -> MediaGate {
            MediaGate::Ready
        }
    }

    fn controller() -> CallController<FakePorts> {
        CallController::new(FakePorts { now: 1_000 })
    }

    #[test]
    fn encoded_offer_results_preserve_controller_state() {
        for ok in [false, true] {
            let mut c = controller();
            assert!(c.dial([1; 32]).is_ok());
            let sends = c.drain_encoded();
            assert_eq!(sends.len(), 1);
            for (_, _, ticket) in sends {
                c.report_send_result(ticket, ok);
            }
            assert_eq!(
                c.status().state,
                if ok { State::Calling } else { State::Idle }
            );
            assert_eq!(c.take_notices().0.contains(&CallNotice::SendFailed), !ok);
        }
    }

    #[test]
    fn queue_overflow_drops_oldest_and_sets_gap() {
        let mut q = NoticeQueue::new();
        for _ in 0..NOTICE_CAPACITY {
            q.push(CallNotice::Connected);
        }
        assert_eq!(q.len(), NOTICE_CAPACITY);
        // One more overflows: oldest dropped, length stays at capacity, gap set.
        q.push(CallNotice::CallEnded);
        assert_eq!(q.len(), NOTICE_CAPACITY);
        let (items, gap) = q.drain();
        assert!(gap);
        assert_eq!(items.len(), NOTICE_CAPACITY);
        // The dropped item was the oldest: the last item is the newest push.
        assert_eq!(*items.last().unwrap(), CallNotice::CallEnded);
    }

    #[test]
    fn drain_reports_gap_once() {
        let mut q = NoticeQueue::new();
        for _ in 0..(NOTICE_CAPACITY + 1) {
            q.push(CallNotice::Connected);
        }
        let (_, gap1) = q.drain();
        assert!(gap1);
        // A second drain with no further overflow reports no gap.
        q.push(CallNotice::Connected);
        let (_, gap2) = q.drain();
        assert!(!gap2);
    }

    #[test]
    fn tokens_are_unique_and_increasing() {
        let mut c = controller();
        let t0 = c.begin_incoming();
        let t1 = c.begin_incoming();
        let t2 = c.begin_incoming();
        assert!(t1 > t0);
        assert!(t2 > t1);
        assert_ne!(t0, t1);
        assert_ne!(t1, t2);
    }

    #[test]
    fn approve_accepts_only_current_token() {
        let mut c = controller();
        let stale = c.begin_incoming();
        // A new incoming call supersedes the stale token.
        let current = c.begin_incoming();
        assert!(!c.approve(stale));
        assert!(c.approve(current));
        // Once approved, the token is cleared and cannot be reused.
        assert!(!c.approve(current));
    }

    #[test]
    fn status_signalling_connected_only_in_connected() {
        let c = controller();
        // A fresh controller is Idle, so signalling is not connected.
        let s = c.status();
        assert_eq!(s.state, State::Idle);
        assert!(!s.signalling_connected);
        assert_eq!(s.pending_token, None);
    }
}
