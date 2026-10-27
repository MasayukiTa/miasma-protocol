//! Call controller ports, user-facing notice queue and the incoming-call
//! approval token (PR5a1).
//!
//! This module sits above the pure [`state::CallMachine`] and owns the small
//! amount of host-facing plumbing the machine deliberately avoids: a [`CallPorts`]
//! trait for the injected clock and contact check, a bounded [`NoticeQueue`] that
//! buffers user-facing notices for a UI to drain, and a per-incoming-call
//! approval token so a stale user interface cannot approve a replacement call.
//!
//! Inbound records and timeouts drive the machine; sending remains for later work.
//!
//! Privacy: anything that holds a call id or a peer id must not derive `Debug`
//! (a call id is secret-adjacent, see [`state`]). [`CallNotice`], [`CallStatus`]
//! and the peer field therefore get a hand-written `Debug` that prints a fixed
//! string only.

use std::collections::VecDeque;

use super::inbound::CallInbound;
use super::signal::Record;
use super::state::{
    CallId, CallMachine, Effect, Event, Notice, Offer, PeerId, State, OFFER_TTL_MS,
};

/// Host services the controller needs but does not own: the clock and the
/// contact check. Injected so the controller stays testable and performs no I/O
/// itself.
pub trait CallPorts {
    /// Current time in milliseconds on the host clock.
    fn now_ms(&self) -> u64;
    /// Whether `peer` (a 32-byte identity) is a known, allowed contact.
    fn is_contact_allowed(&self, peer: &[u8; 32]) -> bool;
}

#[cfg(test)]
mod inbound_tests {
    use super::super::signal::{new_call_id, new_call_nonce, Kind};
    use super::super::state::{Control, Reason};
    use super::*;

    struct Ports {
        now: u64,
        allowed: bool,
    }
    impl CallPorts for Ports {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn is_contact_allowed(&self, _: &[u8; 32]) -> bool {
            self.allowed
        }
    }
    fn controller() -> CallController<Ports> {
        CallController::new(Ports {
            now: 1000,
            allowed: true,
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
            capabilities: vec![],
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
        c.on_inbound(inbound([1; 32], offer(new_call_id(), 100_000)));
        let first = new_call_id();
        c.on_inbound(inbound([2; 32], offer(first, 100_000)));
        for _ in 0..16 {
            c.on_inbound(inbound([2; 32], offer(new_call_id(), 100_000)));
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
    pending_effects: VecDeque<Effect>,
    entered_at_ms: Option<u64>,
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
            pending_effects: VecDeque::with_capacity(16),
            entered_at_ms: None,
        }
    }

    /// Apply an authenticated inbound signalling record.
    pub fn on_inbound(&mut self, inbound: CallInbound) {
        let now = self.ports.now_ms();
        let old_state = self.machine.state();
        let peer = inbound.peer;
        let event = match inbound.signal {
            Record::Offer {
                call_id,
                expires_at_ms,
                ..
            } => Event::ReceivedOffer(Offer {
                call_id: CallId(call_id),
                peer_id: PeerId(peer),
                from_contact: self.ports.is_contact_allowed(&peer),
                expired: expires_at_ms < now,
                other_call_active: old_state != State::Idle,
            }),
            Record::Answer { call_id, .. } if self.peer == Some(peer) => Event::ReceivedAnswer {
                call_id: CallId(call_id),
            },
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
        self.apply_event(event, now);
        if is_offer && old_state != State::Ringing && self.machine.state() == State::Ringing {
            self.peer = Some(peer);
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

    /// Take buffered send effects in order.
    pub fn take_effects(&mut self) -> Vec<Effect> {
        self.pending_effects.drain(..).collect()
    }

    fn apply_event(&mut self, event: Event, now: u64) {
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
                    if self.pending_effects.len() >= 16 {
                        self.pending_effects.pop_front();
                    }
                    self.pending_effects.push_back(effect);
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
        self.next_token += 1;
        self.pending_token = Some(token);
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
    }

    fn controller() -> CallController<FakePorts> {
        CallController::new(FakePorts { now: 1_000 })
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
