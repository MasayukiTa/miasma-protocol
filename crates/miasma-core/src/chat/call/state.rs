//! Pure per-call state machine for the call feature (PR2).
//!
//! This module is the normative state machine of design-call-security-v7e.md
//! chapter 3 (sections 3.5, 3.6 and 3.10). It is pure: it takes the current
//! time as an injected argument, holds no timers, owns no sockets and performs
//! no I/O. Given a state and an event it returns the next state and the list of
//! effects a caller must carry out (what to send, what to show). The signalling
//! layer, the transport and the UI live elsewhere; this file only decides
//! transitions.
//!
//! Scope (goal PR2b): the per-call state machine only. No codec, no outbox, no
//! IPC, no UI, no transport. The media keys, the AEAD and the key schedule are
//! PR1 (`super::media`, `super::frame`); this module never touches key bytes.
//!
//! Privacy: a `call_id` is a 16-byte identifier that binds every control and
//! media record of one call (section 3.2.1). It is a secret-adjacent value: it
//! must not reach a log, an error message or a `Debug` output. Therefore
//! [`CallId`] deliberately does not derive `Debug`, its bytes are compared in
//! constant time, and [`CallMachine`] does not derive `Debug` either. The
//! effects and events that cross this boundary carry no key, nonce, call id,
//! peer id or media sample in any `Debug` form.
//!
//! Completeness (section 3.10.3): every state x every event pair returns a
//! defined result; where the design says to ignore an event, the machine stays
//! in the same state and emits no effect. `step` never panics on any input.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Length of a `call_id` in bytes (section 3.2.1).
pub const CALL_ID_LEN: usize = 16;

/// The offer time-to-live in milliseconds: 45 s (section 3.2.1 / 3.5.6). The
/// machine does not run a timer; a caller injects [`Event::Timeout`] when its
/// own clock crosses this, and the machine also refuses an offer whose
/// `expires_at` is already in the past (see [`Offer::expired`]).
pub const OFFER_TTL_MS: u64 = 45_000;

/// Media-silence timeout in milliseconds: 20 s (section 3.5.6). A connected
/// call with neither media nor keepalive for this long is treated as dropped.
/// Injected as [`Event::MediaSilence`]; kept here as the single source of the
/// number.
pub const MEDIA_SILENCE_MS: u64 = 20_000;

/// A 16-byte call identifier (section 3.2.1).
///
/// No `Debug`: the bytes must never reach a log or error text. Equality is
/// constant time so that comparing a received echo against the active call id
/// does not leak through timing. The deterministic collision tie-break of
/// section 3.6 orders two ids by their 16 bytes in lexicographic order via
/// [`CallId::cmp_bytes`], a plain byte comparison; it need not be constant time
/// because the ordering outcome is public (both peers reach the same result).
#[derive(Clone, Copy)]
pub struct CallId(pub [u8; CALL_ID_LEN]);

impl CallId {
    /// Wrap 16 bytes as a call id.
    #[inline]
    pub fn new(bytes: [u8; CALL_ID_LEN]) -> Self {
        CallId(bytes)
    }

    /// Lexicographic order of the 16 id bytes, the only input to the section
    /// 3.6 tie-break. Does not depend on identity, address, time or any
    /// upper-byte shortcut (section 3.11): the whole 16-byte string decides.
    #[inline]
    pub fn cmp_bytes(&self, other: &CallId) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialEq for CallId {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for CallId {}

/// Opaque peer identifier; never included in Debug output.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerId(pub [u8; 32]);

/// The four states of one call (section 3.10). The end state (the "terminal" /
/// "end state" of chapter 5) is [`State::Idle`]: a call that ends returns here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// No call in progress.
    Idle,
    /// We dialled and sent an offer; waiting for answer/reject/busy (3.5.1).
    Calling,
    /// An incoming offer is ringing; waiting for the user to accept or reject
    /// (3.5.2).
    Ringing,
    /// Media is established (3.5.3). Media itself is PR1/PR5; this state only
    /// records that the call reached it.
    Connected,
}

/// Which role this endpoint plays in the current call. Caller sent the offer;
/// Callee received it. Fixed (and possibly flipped) by the section 3.6
/// tie-break; carried so a later transition knows which control is legitimate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Caller,
    Callee,
}

/// A received `CALL_OFFER`, reduced to exactly what the state machine needs.
/// Body decoding, the AAD check and the gate all run before this reaches the
/// machine (3.2.3 / 3.5.2); the machine only sees the distilled facts.
#[derive(Clone, Copy)]
pub struct Offer {
    /// The offer's call id (3.2.1).
    pub call_id: CallId,
    /// Authenticated sender identity.
    pub peer_id: PeerId,
    /// Whether the sender is a known contact. A non-contact offer is ignored
    /// silently (3.3): no ring, no reject, no busy.
    pub from_contact: bool,
    /// Whether the offer is already past its TTL on our local clock
    /// (`now > expires_at`, 3.8). An expired offer never reaches `Ringing`.
    pub expired: bool,
    /// Whether we are already in another call (connected, or calling/ringing a
    /// different call). When true and the offer is otherwise acceptable we
    /// answer busy (3.5.7).
    pub other_call_active: bool,
}

// No `Debug` for `Offer`: it carries a `CallId`.

/// Reasons placed in an outgoing control message (`reason` field, 3.1.2).
/// Stable, secret-free strings; gate-derived reasons (`pqc_failed`,
/// `pqc_peer_no_hybrid`) are produced by the gate layer, not here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reason {
    /// The callee declined (3.5.4).
    Declined,
    /// The caller withdrew the call (3.5.8).
    Canceled,
    /// The call timed out with no answer (3.5.6).
    Timeout,
    /// Busy: already in another call (3.5.7).
    Busy,
    /// This endpoint lost the simultaneous-offer tie-break (3.6).
    CollisionLost,
    /// Media establishment failed after approval, e.g. a device open failure
    /// (3.10.1): tell the peer the call could not be established.
    EstablishmentFailed,
}

/// The control message kinds the state machine may ask to send (3.1.2). The
/// wire encoding, the envelope seal and the actual transmission are not this
/// module's job.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Control {
    Offer,
    Answer,
    Reject,
    Busy,
    Cancel,
    Bye,
    Collide,
}

/// A user-facing notice the machine asks the UI to show (3.10.1 "show"
/// column). Free of any call id or peer id so it is safe to render or log.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Notice {
    /// Incoming call is ringing; raise the accept/reject UI.
    IncomingRinging,
    /// The outgoing call was rejected by the peer.
    Rejected,
    /// The peer is busy.
    PeerBusy,
    /// No answer within the TTL.
    NoAnswer,
    /// The call is connected.
    Connected,
    /// The call ended (bye, hang up or silence).
    CallEnded,
    /// Media could not be established after approval (device open failure).
    EstablishmentFailed,
    /// Clear any incoming-call UI without further notice.
    ClearIncoming,
}

/// One effect the caller must carry out after a transition (3.10.1 columns
/// "send" and "show", plus key hygiene). The machine returns these; it performs
/// none of them. No `Debug`: it carries a `CallId`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Send a control message carrying this call id and optional reason. The
    /// call id is the echo the peer expects (3.2.1).
    Send {
        control: Control,
        call_id: CallId,
        reason: Option<Reason>,
    },
    /// Respond to a simultaneous offer with both call identifiers.
    Collide {
        call_id: CallId,
        peer_call_id: CallId,
    },
    /// Show a user-facing notice.
    Show(Notice),
    /// Zeroize all media key material and chain state for the call (3.5.5 /
    /// 3.6.2). The key bytes live in PR1; this is the signal to wipe them.
    ZeroizeKeys,
    /// Replace the SAS input (call_nonce / offer_hash / call_id) with the
    /// winner offer's values after losing the section 3.6 tie-break (3.6.1).
    /// The SAS computation itself is chapter 2; this only tells the caller to
    /// switch its input to the adopted call id.
    ReplaceSasInput { adopted: CallId },
}

/// Events fed to the machine (section 3.10). User actions, received control
/// messages and the two injected timeouts. The clock is injected separately
/// into [`CallMachine::step`]; timer firing is the caller's job.
#[derive(Clone, Copy)]
pub enum Event {
    /// User pressed dial (3.5.1). `call_id` is freshly generated by the caller
    /// from `OsRng` (3.2.1); the machine does not generate it.
    UserDial { call_id: CallId, peer_id: PeerId },
    /// User accepted the incoming call (3.5.3).
    UserAccept,
    /// User rejected the incoming call (3.5.4).
    UserReject,
    /// User hung up (3.5.5 / 3.5.8): bye if connected, cancel if calling.
    UserHangUp,
    /// A `CALL_OFFER` was received (3.5.2). Already decoded, AAD-checked and
    /// gate-passed; the distilled facts are in [`Offer`].
    ReceivedOffer(Offer),
    /// A `CALL_ANSWER` with this echoed call id (3.5.3).
    ReceivedAnswer { call_id: CallId },
    /// A `CALL_REJECT` with this echoed call id (3.5.4).
    ReceivedReject { call_id: CallId },
    /// A `CALL_BYE` with this echoed call id (3.5.5).
    ReceivedHangUp { call_id: CallId },
    /// A `CALL_BUSY` with this echoed call id (3.5.7).
    ReceivedBusy { call_id: CallId },
    /// A `CALL_CANCEL` with this echoed call id (3.5.8).
    ReceivedCancel { call_id: CallId },
    /// The 45 s offer TTL elapsed on the local clock (3.5.6).
    Timeout,
    /// 20 s of media silence on a connected call (3.5.6).
    MediaSilence,
    /// After approval and successful media-key acquisition, opening the
    /// audio/video device failed (3.10.1 device-open-failure row).
    DeviceOpenFailed,
}

/// The outcome of one `step`: the (possibly unchanged) state plus the effects.
#[derive(Clone)]
pub struct Transition {
    pub next: State,
    pub effects: Vec<Effect>,
}

impl Transition {
    #[inline]
    fn to(next: State, effects: Vec<Effect>) -> Self {
        Transition { next, effects }
    }

    /// A defined "ignore silently" result: no state change, no effect (3.10.3).
    #[inline]
    fn ignore(state: State) -> Self {
        Transition {
            next: state,
            effects: Vec::new(),
        }
    }
}

/// The per-call state machine (section 3.10). Holds the current state, this
/// endpoint's role and the active call id (when any). No key material, no
/// timers, no I/O. No `Debug`: it holds a `CallId`.
pub struct CallMachine {
    state: State,
    role: Option<Role>,
    active: Option<CallId>,
    peer: Option<PeerId>,
}

impl Default for CallMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl CallMachine {
    /// A fresh machine in `Idle` with no active call.
    #[inline]
    pub fn new() -> Self {
        CallMachine {
            state: State::Idle,
            role: None,
            active: None,
            peer: None,
        }
    }

    #[inline]
    pub fn state(&self) -> State {
        self.state
    }

    #[inline]
    pub fn role(&self) -> Option<Role> {
        self.role
    }

    /// Whether `id` equals the active call id (constant-time, 3.2.1 echo
    /// binding). A control message whose echoed call id does not match the
    /// active call is not ours (3.2.1); the machine treats a mismatch as
    /// "ignore silently".
    #[inline]
    pub fn matches_active(&self, id: &CallId) -> bool {
        match &self.active {
            Some(a) => a == id,
            None => false,
        }
    }

    fn clear(&mut self) {
        self.state = State::Idle;
        self.role = None;
        self.peer = None;
        if let Some(mut id) = self.active.take() {
            // The call id is a secret-adjacent identifier; wipe it on teardown
            // so it does not linger in memory (3.6.2 hygiene, applied to the
            // identifier the machine held).
            id.0.zeroize();
        }
    }

    /// Drive the machine with one event at the injected time `now_ms`
    /// (milliseconds). Returns the next state and the effects to carry out.
    /// Total over state x event (3.10.3); never panics on any input.
    ///
    /// `now_ms` is accepted for every event so the machine stays pure and the
    /// caller owns all timing; the current rows do not branch on its value (the
    /// TTL/silence decisions arrive pre-computed as `expired` on an [`Offer`]
    /// and as the `Timeout` / `MediaSilence` events).
    pub fn step(&mut self, event: Event, now_ms: u64) -> Transition {
        let _ = now_ms;
        match (self.state, event) {
            // ---- idle ----
            (State::Idle, Event::UserDial { call_id, peer_id }) => {
                self.state = State::Calling;
                self.role = Some(Role::Caller);
                self.active = Some(call_id);
                self.peer = Some(peer_id);
                Transition::to(
                    State::Calling,
                    vec![Effect::Send {
                        control: Control::Offer,
                        call_id,
                        reason: None,
                    }],
                )
            }
            (State::Idle, Event::ReceivedOffer(offer)) => self.on_offer_idle(offer),

            // ---- calling ----
            (State::Calling, Event::ReceivedAnswer { call_id }) => {
                if self.matches_active(&call_id) {
                    self.state = State::Connected;
                    Transition::to(State::Connected, vec![Effect::Show(Notice::Connected)])
                } else {
                    Transition::ignore(State::Calling)
                }
            }
            (State::Calling, Event::ReceivedReject { call_id }) => {
                if self.matches_active(&call_id) {
                    self.clear();
                    Transition::to(State::Idle, vec![Effect::Show(Notice::Rejected)])
                } else {
                    Transition::ignore(State::Calling)
                }
            }
            (State::Calling, Event::ReceivedBusy { call_id }) => {
                if self.matches_active(&call_id) {
                    self.clear();
                    Transition::to(State::Idle, vec![Effect::Show(Notice::PeerBusy)])
                } else {
                    Transition::ignore(State::Calling)
                }
            }
            (State::Calling, Event::Timeout) => {
                let id = self.active;
                self.clear();
                let mut effects = Vec::new();
                if let Some(call_id) = id {
                    effects.push(Effect::Send {
                        control: Control::Cancel,
                        call_id,
                        reason: Some(Reason::Timeout),
                    });
                }
                effects.push(Effect::Show(Notice::NoAnswer));
                Transition::to(State::Idle, effects)
            }
            (State::Calling, Event::UserHangUp) => {
                let id = self.active;
                self.clear();
                let mut effects = Vec::new();
                if let Some(call_id) = id {
                    effects.push(Effect::Send {
                        control: Control::Cancel,
                        call_id,
                        reason: Some(Reason::Canceled),
                    });
                }
                Transition::to(State::Idle, effects)
            }
            (State::Calling, Event::ReceivedOffer(offer)) => self.on_offer_calling(offer),

            // ---- ringing ----
            (State::Ringing, Event::UserAccept) => match self.active {
                Some(call_id) => {
                    self.state = State::Connected;
                    Transition::to(
                        State::Connected,
                        vec![
                            Effect::Send {
                                control: Control::Answer,
                                call_id,
                                reason: None,
                            },
                            Effect::Show(Notice::Connected),
                        ],
                    )
                }
                None => Transition::ignore(State::Ringing),
            },
            (State::Ringing | State::Connected, Event::DeviceOpenFailed) => {
                // Approved and media key obtained, but the device open failed:
                // return to Idle, tell the peer the
                // call could not be established, and zeroize key material
                // (3.10.1 device-open-failure row).
                let id = self.active;
                let control = if self.state == State::Connected {
                    Control::Bye
                } else {
                    Control::Reject
                };
                self.clear();
                let mut effects = Vec::new();
                if let Some(call_id) = id {
                    effects.push(Effect::Send {
                        control,
                        call_id,
                        reason: Some(Reason::EstablishmentFailed),
                    });
                }
                effects.push(Effect::ZeroizeKeys);
                effects.push(Effect::Show(Notice::EstablishmentFailed));
                Transition::to(State::Idle, effects)
            }
            (State::Ringing, Event::UserReject) => {
                let id = self.active;
                self.clear();
                let mut effects = Vec::new();
                if let Some(call_id) = id {
                    effects.push(Effect::Send {
                        control: Control::Reject,
                        call_id,
                        reason: Some(Reason::Declined),
                    });
                }
                Transition::to(State::Idle, effects)
            }
            (State::Ringing, Event::ReceivedCancel { call_id }) => {
                if self.matches_active(&call_id) {
                    self.clear();
                    Transition::to(State::Idle, vec![Effect::Show(Notice::ClearIncoming)])
                } else {
                    Transition::ignore(State::Ringing)
                }
            }
            (State::Ringing, Event::Timeout) => {
                self.clear();
                Transition::to(State::Idle, vec![Effect::Show(Notice::ClearIncoming)])
            }
            // Ringing + user dial to the same peer: suppress the dial, keep
            // handling the incoming call (3.10.1 / 3.10.3). Not a collision.
            (State::Ringing, Event::UserDial { .. }) => Transition::ignore(State::Ringing),

            // ---- connected ----
            (State::Connected, Event::ReceivedHangUp { call_id }) => {
                if self.matches_active(&call_id) {
                    self.clear();
                    Transition::to(
                        State::Idle,
                        vec![Effect::ZeroizeKeys, Effect::Show(Notice::CallEnded)],
                    )
                } else {
                    Transition::ignore(State::Connected)
                }
            }
            (State::Connected, Event::UserHangUp) => {
                let id = self.active;
                self.clear();
                let mut effects = Vec::new();
                if let Some(call_id) = id {
                    effects.push(Effect::Send {
                        control: Control::Bye,
                        call_id,
                        reason: None,
                    });
                }
                effects.push(Effect::ZeroizeKeys);
                effects.push(Effect::Show(Notice::CallEnded));
                Transition::to(State::Idle, effects)
            }
            (State::Connected, Event::MediaSilence) => {
                self.clear();
                Transition::to(
                    State::Idle,
                    vec![Effect::ZeroizeKeys, Effect::Show(Notice::CallEnded)],
                )
            }

            (state @ (State::Ringing | State::Connected), Event::ReceivedOffer(offer)) => {
                if !offer.from_contact || offer.expired {
                    Transition::ignore(state)
                } else {
                    Transition::to(
                        state,
                        vec![Effect::Send {
                            control: Control::Busy,
                            call_id: offer.call_id,
                            reason: Some(Reason::Busy),
                        }],
                    )
                }
            }

            // ---- everything else: ignore silently (3.10.3 completeness) ----
            //
            // This arm makes the machine total over state x event. It covers:
            // state-reachable-but-impossible known-call-id control (e.g. an
            // ANSWER in Idle, a BYE in Calling); user actions that do not apply in the current state;
            // and a Timeout / MediaSilence / DeviceOpenFailed in a state where
            // they have no meaning. All leave the state unchanged and emit no
            // effect, exactly as 3.10.3 prescribes for silent ignore.
            (state, _) => Transition::ignore(state),
        }
    }

    /// `CALL_OFFER` received in `Idle` (3.5.2 / 3.10.1).
    fn on_offer_idle(&mut self, offer: Offer) -> Transition {
        // Non-contact: ignore silently. No ring, no reject, no busy (3.3).
        if !offer.from_contact {
            return Transition::ignore(State::Idle);
        }
        // Expired offer never reaches Ringing: drop as a ghost (3.8). Silent.
        if offer.expired {
            return Transition::ignore(State::Idle);
        }
        // Already in another call: answer busy, do not ring (3.5.7).
        if offer.other_call_active {
            return Transition::to(
                State::Idle,
                vec![Effect::Send {
                    control: Control::Busy,
                    call_id: offer.call_id,
                    reason: Some(Reason::Busy),
                }],
            );
        }

        // Accept into Ringing (3.5.2 step 8).
        self.state = State::Ringing;
        self.role = Some(Role::Callee);
        self.active = Some(offer.call_id);
        self.peer = Some(offer.peer_id);
        Transition::to(State::Ringing, vec![Effect::Show(Notice::IncomingRinging)])
    }

    /// Resolve an unexpired simultaneous offer from the current peer (3.6).
    fn on_offer_calling(&mut self, offer: Offer) -> Transition {
        // A non-contact offer is ignored silently even mid-call (3.3).
        if !offer.from_contact {
            return Transition::ignore(State::Calling);
        }
        if offer.expired {
            return Transition::ignore(State::Calling);
        }
        if self.peer != Some(offer.peer_id) || offer.other_call_active {
            return Transition::to(
                State::Calling,
                vec![Effect::Send {
                    control: Control::Busy,
                    call_id: offer.call_id,
                    reason: Some(Reason::Busy),
                }],
            );
        }
        let ours = match self.active {
            Some(id) => id,
            // No active id while Calling should not happen; ignore for safety.
            None => return Transition::ignore(State::Calling),
        };
        // Deterministic tie-break on the full 16 call_id bytes (3.6).
        match ours.cmp_bytes(&offer.call_id) {
            core::cmp::Ordering::Less => {
                // We are smaller: we win, stay the caller. Answer the peer's
                // offer with CALL_COLLIDE and keep waiting for our answer.
                Transition::to(
                    State::Calling,
                    vec![Effect::Collide {
                        call_id: ours,
                        peer_call_id: offer.call_id,
                    }],
                )
            }
            core::cmp::Ordering::Greater => {
                // We are larger: we lose. Withdraw our offer (cancel,
                // collision_lost), become the callee of the peer's offer, drop
                // and zeroize the half-built MK_root, and replace the SAS input
                // with the adopted (winner) offer's values (3.6 / 3.6.1).
                let lost = ours;
                let adopted = offer.call_id;
                self.state = State::Ringing;
                self.role = Some(Role::Callee);
                if let Some(id) = self.active.as_mut() {
                    id.0.zeroize();
                }
                self.active = Some(adopted);
                Transition::to(
                    State::Ringing,
                    vec![
                        Effect::Send {
                            control: Control::Cancel,
                            call_id: lost,
                            reason: Some(Reason::CollisionLost),
                        },
                        Effect::ZeroizeKeys,
                        Effect::ReplaceSasInput { adopted },
                        Effect::Show(Notice::IncomingRinging),
                    ],
                )
            }
            core::cmp::Ordering::Equal => {
                // 16-byte equal (astronomically rare): both drop and re-dial.
                self.clear();
                Transition::to(State::Idle, vec![Effect::ZeroizeKeys])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // All tests generate call ids at run time; no fixed identifiers (chapter 7
    // rule). A call id is not a key, but we still never hard-code one.
    fn rand_id() -> CallId {
        CallId::new(std::array::from_fn(|_| rand::random::<u8>()))
    }

    fn test_peer() -> PeerId {
        PeerId([1; 32])
    }

    // A call id strictly less than `base` by its byte string, for deterministic
    // tie-break tests. Returns None if `base` is all-zero (no smaller id).
    fn id_below(base: &CallId) -> Option<CallId> {
        let mut b = base.0;
        for i in (0..CALL_ID_LEN).rev() {
            if b[i] > 0 {
                b[i] -= 1;
                return Some(CallId::new(b));
            }
            b[i] = 0xff;
        }
        None
    }

    fn offer(call_id: CallId, from_contact: bool, expired: bool, other_call_active: bool) -> Offer {
        Offer {
            call_id,
            peer_id: test_peer(),
            from_contact,
            expired,
            other_call_active,
        }
    }

    fn good_offer(call_id: CallId) -> Offer {
        offer(call_id, true, false, false)
    }

    // Drive a fresh machine into Calling as the caller of `id`.
    fn calling(id: CallId) -> CallMachine {
        let mut m = CallMachine::new();
        let t = m.step(
            Event::UserDial {
                call_id: id,
                peer_id: test_peer(),
            },
            1_000,
        );
        assert_eq!(t.next, State::Calling);
        m
    }

    // Drive a fresh machine into Ringing as the callee of `id`.
    fn ringing(id: CallId) -> CallMachine {
        let mut m = CallMachine::new();
        let t = m.step(Event::ReceivedOffer(good_offer(id)), 1_000);
        assert_eq!(t.next, State::Ringing);
        m
    }

    // Drive a fresh machine into Connected as the caller of `id`.
    fn connected(id: CallId) -> CallMachine {
        let mut m = calling(id);
        let t = m.step(Event::ReceivedAnswer { call_id: id }, 2_000);
        assert_eq!(t.next, State::Connected);
        m
    }

    fn has_send(effects: &[Effect], want: Control) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::Send { control, .. } if *control == want))
    }

    fn has_show(effects: &[Effect], want: Notice) -> bool {
        effects
            .iter()
            .any(|e| matches!(e, Effect::Show(n) if *n == want))
    }

    fn has_zeroize(effects: &[Effect]) -> bool {
        effects.iter().any(|e| matches!(e, Effect::ZeroizeKeys))
    }

    // ---- one test per row of the 3.10.1 / 3.10.2 transition table ----

    // Row: idle + user dial (gate Proceed) -> calling, send OFFER.
    #[test]
    fn row_idle_dial() {
        let id = rand_id();
        let mut m = CallMachine::new();
        let t = m.step(
            Event::UserDial {
                call_id: id,
                peer_id: test_peer(),
            },
            10,
        );
        assert_eq!(t.next, State::Calling);
        assert_eq!(m.role(), Some(Role::Caller));
        assert!(has_send(&t.effects, Control::Offer));
    }

    // Row: idle + OFFER (contact, in TTL, no other call) -> ringing, show.
    #[test]
    fn row_idle_offer_accept() {
        let id = rand_id();
        let mut m = CallMachine::new();
        let t = m.step(Event::ReceivedOffer(good_offer(id)), 10);
        assert_eq!(t.next, State::Ringing);
        assert_eq!(m.role(), Some(Role::Callee));
        assert!(has_show(&t.effects, Notice::IncomingRinging));
    }

    // Row: idle + OFFER (non-contact) -> idle, silent (no ring, no reject).
    #[test]
    fn row_idle_offer_non_contact() {
        let id = rand_id();
        let mut m = CallMachine::new();
        let t = m.step(Event::ReceivedOffer(offer(id, false, false, false)), 10);
        assert_eq!(t.next, State::Idle);
        assert!(t.effects.is_empty());
    }

    // Row: idle + OFFER (contact, past TTL) -> idle, silent (ghost).
    #[test]
    fn row_idle_offer_expired() {
        let id = rand_id();
        let mut m = CallMachine::new();
        let t = m.step(Event::ReceivedOffer(offer(id, true, true, false)), 10);
        assert_eq!(t.next, State::Idle);
        assert!(t.effects.is_empty());
    }

    // Row: idle + OFFER while in another call -> send BUSY, state unchanged.
    #[test]
    fn row_idle_offer_other_call_busy() {
        let id = rand_id();
        let mut m = CallMachine::new();
        let t = m.step(Event::ReceivedOffer(offer(id, true, false, true)), 10);
        assert_eq!(t.next, State::Idle);
        assert!(has_send(&t.effects, Control::Busy));
    }

    // Row: calling + ANSWER (matching id) -> connected, show Connected.
    #[test]
    fn row_calling_answer() {
        let id = rand_id();
        let mut m = calling(id);
        let t = m.step(Event::ReceivedAnswer { call_id: id }, 20);
        assert_eq!(t.next, State::Connected);
        assert!(has_show(&t.effects, Notice::Connected));
    }

    // Row: calling + REJECT (matching id) -> idle, show Rejected.
    #[test]
    fn row_calling_reject() {
        let id = rand_id();
        let mut m = calling(id);
        let t = m.step(Event::ReceivedReject { call_id: id }, 20);
        assert_eq!(t.next, State::Idle);
        assert!(has_show(&t.effects, Notice::Rejected));
    }

    // Row: calling + BUSY (matching id) -> idle, show PeerBusy.
    #[test]
    fn row_calling_busy() {
        let id = rand_id();
        let mut m = calling(id);
        let t = m.step(Event::ReceivedBusy { call_id: id }, 20);
        assert_eq!(t.next, State::Idle);
        assert!(has_show(&t.effects, Notice::PeerBusy));
    }

    // Row: calling + timeout -> idle, send CANCEL(timeout), show NoAnswer.
    #[test]
    fn row_calling_timeout() {
        let id = rand_id();
        let mut m = calling(id);
        let t = m.step(Event::Timeout, OFFER_TTL_MS + 1);
        assert_eq!(t.next, State::Idle);
        assert!(has_send(&t.effects, Control::Cancel));
        assert!(has_show(&t.effects, Notice::NoAnswer));
    }

    // Row: calling + user hang up -> idle, send CANCEL(canceled).
    #[test]
    fn row_calling_hangup() {
        let id = rand_id();
        let mut m = calling(id);
        let t = m.step(Event::UserHangUp, 20);
        assert_eq!(t.next, State::Idle);
        assert!(has_send(&t.effects, Control::Cancel));
    }

    // Row: ringing + user accept -> connected, send ANSWER, show Connected.
    #[test]
    fn row_ringing_accept() {
        let id = rand_id();
        let mut m = ringing(id);
        let t = m.step(Event::UserAccept, 20);
        assert_eq!(t.next, State::Connected);
        assert!(has_send(&t.effects, Control::Answer));
        assert!(has_show(&t.effects, Notice::Connected));
    }

    // Row: ringing + approved device-open failure -> idle, tell peer
    // establishment failed, zeroize keys, show EstablishmentFailed.
    #[test]
    fn row_ringing_device_open_failed() {
        let id = rand_id();
        let mut m = ringing(id);
        let t = m.step(Event::DeviceOpenFailed, 20);
        assert_eq!(t.next, State::Idle);
        assert!(matches!(
            t.effects.iter().find(|e| matches!(e, Effect::Send { .. })),
            Some(Effect::Send {
                control: Control::Reject,
                reason: Some(Reason::EstablishmentFailed),
                ..
            })
        ));
        assert!(has_zeroize(&t.effects));
        assert!(has_show(&t.effects, Notice::EstablishmentFailed));
    }

    // Row: ringing + user reject -> idle, send REJECT(declined).
    #[test]
    fn row_ringing_reject() {
        let id = rand_id();
        let mut m = ringing(id);
        let t = m.step(Event::UserReject, 20);
        assert_eq!(t.next, State::Idle);
        assert!(has_send(&t.effects, Control::Reject));
    }

    // Row: ringing + CANCEL (matching id) -> idle, clear incoming UI.
    #[test]
    fn row_ringing_cancel() {
        let id = rand_id();
        let mut m = ringing(id);
        let t = m.step(Event::ReceivedCancel { call_id: id }, 20);
        assert_eq!(t.next, State::Idle);
        assert!(has_show(&t.effects, Notice::ClearIncoming));
    }

    // Row: ringing + user dial (same peer) -> suppressed, stay ringing.
    #[test]
    fn row_ringing_user_dial_suppressed() {
        let id = rand_id();
        let mut m = ringing(id);
        let t = m.step(
            Event::UserDial {
                call_id: rand_id(),
                peer_id: test_peer(),
            },
            20,
        );
        assert_eq!(t.next, State::Ringing);
        assert!(t.effects.is_empty());
    }

    // Row: ringing + timeout -> idle, clear incoming UI.
    #[test]
    fn row_ringing_timeout() {
        let id = rand_id();
        let mut m = ringing(id);
        let t = m.step(Event::Timeout, OFFER_TTL_MS + 1);
        assert_eq!(t.next, State::Idle);
        assert!(has_show(&t.effects, Notice::ClearIncoming));
    }

    // Row: connected + BYE (matching id) -> idle, zeroize, show CallEnded.
    #[test]
    fn row_connected_received_bye() {
        let id = rand_id();
        let mut m = connected(id);
        let t = m.step(Event::ReceivedHangUp { call_id: id }, 30);
        assert_eq!(t.next, State::Idle);
        assert!(has_zeroize(&t.effects));
        assert!(has_show(&t.effects, Notice::CallEnded));
    }

    // Row: connected + user hang up -> idle, send BYE, zeroize, show CallEnded.
    #[test]
    fn row_connected_user_hangup() {
        let id = rand_id();
        let mut m = connected(id);
        let t = m.step(Event::UserHangUp, 30);
        assert_eq!(t.next, State::Idle);
        assert!(has_send(&t.effects, Control::Bye));
        assert!(has_zeroize(&t.effects));
        assert!(has_show(&t.effects, Notice::CallEnded));
    }

    // Row: connected + 20 s media silence -> idle, zeroize, show CallEnded.
    #[test]
    fn row_connected_media_silence() {
        let id = rand_id();
        let mut m = connected(id);
        let t = m.step(Event::MediaSilence, MEDIA_SILENCE_MS + 1);
        assert_eq!(t.next, State::Idle);
        assert!(has_zeroize(&t.effects));
        assert!(has_show(&t.effects, Notice::CallEnded));
    }

    // Row (any state): state-reachable-but-impossible known-call-id control is
    // ignored silently (e.g. ANSWER in idle, BYE in calling).
    #[test]
    fn row_impossible_known_control_ignored() {
        let id = rand_id();
        let mut m = CallMachine::new();
        let t = m.step(Event::ReceivedAnswer { call_id: id }, 10);
        assert_eq!(t.next, State::Idle);
        assert!(t.effects.is_empty());

        let mut m2 = calling(id);
        let t2 = m2.step(Event::ReceivedHangUp { call_id: id }, 10);
        assert_eq!(t2.next, State::Calling);
        assert!(t2.effects.is_empty());
    }

    // 3.10.2 row: calling + different-id offer, we are smaller -> win, send
    // COLLIDE, stay calling.
    #[test]
    fn row_collision_win() {
        let ours = rand_id();
        let smaller = match id_below(&ours) {
            Some(s) => s,
            None => return, // all-zero ours: no smaller peer id, skip
        };
        // ours > smaller, so peer offer carries `smaller`: we are larger -> lose.
        // Flip so we are the smaller: dial `smaller`, peer offers `ours`.
        let mut m = calling(smaller);
        let t = m.step(Event::ReceivedOffer(good_offer(ours)), 20);
        assert_eq!(t.next, State::Calling);
        assert!(
            matches!(t.effects.as_slice(), [Effect::Collide { call_id, peer_call_id }] if *call_id == smaller && *peer_call_id == ours)
        );
        assert_eq!(m.role(), Some(Role::Caller));
    }

    // 3.10.2 row: calling + different-id offer, we are larger -> lose, cancel,
    // zeroize, replace SAS input, ring as callee.
    #[test]
    fn row_collision_lose() {
        let ours = rand_id();
        let smaller = match id_below(&ours) {
            Some(s) => s,
            None => return,
        };
        let mut m = calling(ours);
        let t = m.step(Event::ReceivedOffer(good_offer(smaller)), 20);
        assert_eq!(t.next, State::Ringing);
        assert_eq!(m.role(), Some(Role::Callee));
        assert!(matches!(
            t.effects.iter().find(|e| matches!(e, Effect::Send { .. })),
            Some(Effect::Send {
                reason: Some(Reason::CollisionLost),
                ..
            })
        ));
        assert!(has_zeroize(&t.effects));
        assert!(t
            .effects
            .iter()
            .any(|e| matches!(e, Effect::ReplaceSasInput { adopted } if *adopted == smaller)));
        assert!(has_show(&t.effects, Notice::IncomingRinging));
    }

    // 3.10.2 row: calling + identical-id offer (16-byte equal) -> both drop and
    // re-dial (idle, zeroize).
    #[test]
    fn row_collision_equal() {
        let id = rand_id();
        let mut m = calling(id);
        let t = m.step(Event::ReceivedOffer(good_offer(id)), 20);
        assert_eq!(t.next, State::Idle);
        assert!(has_zeroize(&t.effects));
    }

    // ---- exhaustive totality: every state x every event is defined ----
    #[test]
    fn every_state_event_pair_is_defined() {
        let id = rand_id();
        let states = [
            State::Idle,
            State::Calling,
            State::Ringing,
            State::Connected,
        ];
        let events = [
            Event::UserDial {
                call_id: id,
                peer_id: test_peer(),
            },
            Event::UserAccept,
            Event::UserReject,
            Event::UserHangUp,
            Event::ReceivedOffer(good_offer(id)),
            Event::ReceivedAnswer { call_id: id },
            Event::ReceivedReject { call_id: id },
            Event::ReceivedHangUp { call_id: id },
            Event::ReceivedBusy { call_id: id },
            Event::ReceivedCancel { call_id: id },
            Event::Timeout,
            Event::MediaSilence,
            Event::DeviceOpenFailed,
        ];
        for &s in &states {
            for &ev in &events {
                // Reconstruct a machine in state `s` with a known active id.
                let mut m = match s {
                    State::Idle => CallMachine::new(),
                    State::Calling => calling(id),
                    State::Ringing => ringing(id),
                    State::Connected => connected(id),
                };
                // Must return a defined Transition with a valid next state and
                // never panic. (A panic would fail the test outright.)
                let t = m.step(ev, 1_000);
                assert!(matches!(
                    t.next,
                    State::Idle | State::Calling | State::Ringing | State::Connected
                ));
            }
        }
    }

    // ---- collision resolves identically on both ends for random id pairs ----
    #[test]
    fn collision_both_ends_agree() {
        for _ in 0..256 {
            let a = rand_id();
            let b = rand_id();
            if a == b {
                continue;
            }
            // End A dialled `a`, receives B's offer `b`.
            let mut ma = calling(a);
            let ta = ma.step(Event::ReceivedOffer(good_offer(b)), 100);
            // End B dialled `b`, receives A's offer `a`.
            let mut mb = calling(b);
            let tb = mb.step(Event::ReceivedOffer(good_offer(a)), 100);
            // Exactly one ends up the caller (calling) and the other the callee
            // (ringing): the roles are complementary, never both-caller or
            // both-callee.
            let a_caller = ta.next == State::Calling && ma.role() == Some(Role::Caller);
            let b_caller = tb.next == State::Calling && mb.role() == Some(Role::Caller);
            let a_callee = ta.next == State::Ringing && ma.role() == Some(Role::Callee);
            let b_callee = tb.next == State::Ringing && mb.role() == Some(Role::Callee);
            assert!((a_caller && b_callee) || (b_caller && a_callee));
            // The adopted (winner) call id is the lexicographically smaller one,
            // identically on both ends.
            let winner = if a.cmp_bytes(&b) == core::cmp::Ordering::Less {
                a
            } else {
                b
            };
            let loser_machine = if a_callee { &ma } else { &mb };
            // The callee's active id is the adopted winner id.
            assert!(loser_machine.matches_active(&winner));
        }
    }

    // 16-byte-equal collision: both ends drop and re-dial.
    #[test]
    fn collision_both_ends_equal_redial() {
        let id = rand_id();
        let mut a = calling(id);
        let mut b = calling(id);
        for machine in [&mut a, &mut b] {
            let t = machine.step(Event::ReceivedOffer(good_offer(id)), 20);
            assert_eq!(t.next, State::Idle);
            assert!(has_zeroize(&t.effects));
        }
    }

    // ---- an expired offer never reaches ringing ----
    #[test]
    fn expired_offer_never_rings() {
        for _ in 0..64 {
            let id = rand_id();
            let mut m = CallMachine::new();
            let t = m.step(Event::ReceivedOffer(offer(id, true, true, false)), 1_000);
            assert_eq!(t.next, State::Idle);
            assert_ne!(t.next, State::Ringing);
            assert!(t.effects.is_empty());
        }
    }

    // ---- a non-contact offer is ignored silently ----
    #[test]
    fn non_contact_offer_ignored_silently() {
        for _ in 0..64 {
            let id = rand_id();
            let mut m = CallMachine::new();
            let t = m.step(Event::ReceivedOffer(offer(id, false, false, false)), 1_000);
            assert_eq!(t.next, State::Idle);
            assert!(t.effects.is_empty());
        }
        // Also mid-call (calling): a non-contact offer must not perturb state.
        let id = rand_id();
        let mut m = calling(id);
        let t = m.step(
            Event::ReceivedOffer(offer(rand_id(), false, false, false)),
            1_000,
        );
        assert_eq!(t.next, State::Calling);
        assert!(t.effects.is_empty());
    }

    #[test]
    fn active_call_offer_is_busy() {
        let id = rand_id();
        let incoming = rand_id();
        for mut m in [ringing(id), connected(id)] {
            let state = m.state();
            let t = m.step(Event::ReceivedOffer(good_offer(incoming)), 20);
            assert_eq!(t.next, state);
            assert!(matches!(t.effects.as_slice(), [Effect::Send {
                control: Control::Busy, call_id, reason: Some(Reason::Busy)
            }] if *call_id == incoming));
            assert!(m.matches_active(&id));
        }
    }

    #[test]
    fn mismatched_control_id_is_ignored() {
        let id = rand_id();
        let mut other = id;
        other.0[0] ^= 1;
        let mut m = connected(id);
        let t = m.step(Event::ReceivedHangUp { call_id: other }, 20);
        assert_eq!(t.next, State::Connected);
        assert!(t.effects.is_empty());
        assert!(m.matches_active(&id));
    }

    #[test]
    fn connected_device_open_failed() {
        let id = rand_id();
        let mut m = ringing(id);
        m.step(Event::UserAccept, 20);
        let t = m.step(Event::DeviceOpenFailed, 21);
        assert_eq!(t.next, State::Idle);
        assert!(matches!(t.effects.as_slice(), [Effect::Send {
            control: Control::Bye, call_id, reason: Some(Reason::EstablishmentFailed)
        }, Effect::ZeroizeKeys, Effect::Show(Notice::EstablishmentFailed)] if *call_id == id));
    }

    #[test]
    fn calling_offer_checks_peer_and_expiry() {
        let id = rand_id();
        let mut m = calling(id);
        let mut incoming = good_offer(rand_id());
        incoming.peer_id = PeerId([2; 32]);
        incoming.expired = true;
        incoming.other_call_active = true;
        let t = m.step(Event::ReceivedOffer(incoming), 20);
        assert_eq!(t.next, State::Calling);
        assert!(t.effects.is_empty());
        incoming.expired = false;
        let t = m.step(Event::ReceivedOffer(incoming), 20);
        assert_eq!(t.next, State::Calling);
        assert!(matches!(t.effects.as_slice(), [Effect::Send {
            control: Control::Busy, call_id, reason: Some(Reason::Busy)
        }] if *call_id == incoming.call_id));
        assert!(m.matches_active(&id));
    }

    #[test]
    fn expired_offer_with_other_call_is_ignored() {
        let mut m = CallMachine::new();
        let t = m.step(Event::ReceivedOffer(offer(rand_id(), true, true, true)), 20);
        assert_eq!(t.next, State::Idle);
        assert!(t.effects.is_empty());
    }

    // ---- privacy: no call id leaks through Debug (types must not derive it) ----
    // This is a compile-time guarantee (CallId/Offer/Effect/CallMachine have no
    // Debug). We assert the public enums that are safe to log do derive Debug.
    #[test]
    fn safe_enums_are_debuggable() {
        let _ = format!("{:?}", State::Idle);
        let _ = format!("{:?}", Role::Caller);
        let _ = format!("{:?}", Control::Offer);
        let _ = format!("{:?}", Notice::Connected);
        let _ = format!("{:?}", Reason::Declined);
    }
}
