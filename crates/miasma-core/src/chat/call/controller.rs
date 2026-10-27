//! Call controller ports, user-facing notice queue and the incoming-call
//! approval token (PR5a1).
//!
//! This module sits above the pure [`state::CallMachine`] and owns the small
//! amount of host-facing plumbing the machine deliberately avoids: a [`CallPorts`]
//! trait for the injected clock and contact check, a bounded [`NoticeQueue`] that
//! buffers user-facing notices for a UI to drain, and a per-incoming-call
//! approval token so a stale user interface cannot approve a replacement call.
//!
//! Scope: this change wires ports, the notice queue and the approval token only.
//! It does NOT implement sending, encoding or message handling; those remain the
//! caller's job and arrive in later work. The controller holds a [`CallMachine`]
//! but this change does not yet feed it events.
//!
//! Privacy: anything that holds a call id or a peer id must not derive `Debug`
//! (a call id is secret-adjacent, see [`state`]). [`CallNotice`], [`CallStatus`]
//! and the peer field therefore get a hand-written `Debug` that prints a fixed
//! string only.

use std::collections::VecDeque;

use super::state::{CallMachine, Notice, State};

/// Host services the controller needs but does not own: the clock and the
/// contact check. Injected so the controller stays testable and performs no I/O
/// itself.
pub trait CallPorts {
    /// Current time in milliseconds on the host clock.
    fn now_ms(&self) -> u64;
    /// Whether `peer` (a 32-byte identity) is a known, allowed contact.
    fn is_contact_allowed(&self, peer: &[u8; 32]) -> bool;
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
/// incoming-call approval token state. This change does not yet drive the
/// machine with events; it wires the token and queue only.
pub struct CallController<P: CallPorts> {
    // Held for later work (driving the machine and the contact check); not yet
    // read in this ports-only change.
    #[allow(dead_code)]
    ports: P,
    machine: CallMachine,
    // The active peer identity, set when a call becomes active in later work.
    #[allow(dead_code)]
    peer: Option<[u8; 32]>,
    notices: NoticeQueue,
    pending_token: Option<u64>,
    next_token: u64,
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
