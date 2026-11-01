//! The network side of group chat: accepts group connections and delivers
//! what members are owed.
//!
//! Identity is `Connection::remote_id()`, proven by the handshake. A peer may
//! open a group connection when it appears in a group we hold or is a trusted
//! contact (who may bring an invitation); anyone else is closed with 403. That
//! check is repeated for every stream. Membership of a particular group, and
//! the rule for each record, are decided by [`GroupCore`].
//!
//! Delivery mirrors the private chat: one worker task per member with
//! something waiting, which dials the member (own ALPN), seals the oldest
//! item on the pairwise session, sends it on a fresh stream and waits for the
//! acknowledgement. Failures wait (the schedule of [`ChatSettings`]); a
//! connection from the member wakes the worker at once.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use iroh::endpoint::Connection;
use tokio::sync::{watch, Notify, Semaphore};
use tracing::{debug, info, warn};

use super::{
    engine::{GroupCore, Work},
    store::GroupStore,
};
use crate::{
    chat::{
        activity::ChatActivity,
        engine::{now_ms, PrepareError},
        proto::{
            self, Ack, AckStatus, Frame, CLOSE_BAD_REQUEST, CLOSE_NOT_ALLOWED, CLOSE_OK,
            CLOSE_RATE, CLOSE_UNSUPPORTED,
        },
        service::{closed_with, envelope_id_of, Buckets, ChatService, ChatSettings},
    },
    push::{contact::fingerprint, store::ContactStore},
    state_crypto::StateKeys,
    transport::iroh_direct::{ChatConnectionHandler, IrohClientError, IrohNode, GROUP_ALPN},
};

const MAX_STREAMS_PER_CONNECTION: usize = 10_000;
const MAX_CONNECTIONS: usize = 16;
const MAX_BAD_IN_A_ROW: u32 = 3;
const MAX_RESETS: u32 = 2;
/// Messages accepted from a member who is not a trusted contact.
const UNVERIFIED_BURST: f64 = 6.0;
const UNVERIFIED_PER_MINUTE: f64 = 6.0;

struct Worker {
    wake: Arc<Notify>,
}

enum Outcome {
    Delivered,
    Permanent(&'static str),
    Retry(&'static str),
    ResetSession,
    /// The item to send changed while we looked (nothing to do now).
    Skip,
}

pub struct GroupService {
    core: Arc<GroupCore>,
    contacts: Arc<ContactStore>,
    node: Arc<IrohNode>,
    settings: ChatSettings,
    trusted_rate: Mutex<Buckets>,
    unverified_rate: Mutex<Buckets>,
    unknown: Mutex<Buckets>,
    slots: Arc<Semaphore>,
    workers: Mutex<HashMap<[u8; 32], Worker>>,
    shutdown: watch::Sender<bool>,
    /// The node-wide chat-send counter, shared with private chat and the push
    /// send loop. Raised while a group send holds the uplink.
    activity: ChatActivity,
}

impl GroupService {
    /// Start group chat next to a running chat service and install it as the
    /// handler of the group ALPN.
    pub fn start(
        chat: &Arc<ChatService>,
        seed: &[u8; 32],
        keys: Arc<StateKeys>,
    ) -> Option<Arc<Self>> {
        let core_chat = chat.core().clone();
        let store_settings = core_chat.store.settings().clone();
        let store = match GroupStore::open(
            core_chat.store.dir(),
            keys,
            core_chat.own_id(),
            store_settings,
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("group chat stays off: {e}");
                return None;
            }
        };
        let core = Arc::new(GroupCore::new(core_chat, store, seed)?);
        Self::start_with(
            core,
            chat.node().clone(),
            chat.contacts().clone(),
            chat.settings().clone(),
            chat.chat_activity().clone(),
        )
    }

    /// As [`start`](Self::start) from parts (tests).
    pub fn start_with(
        core: Arc<GroupCore>,
        node: Arc<IrohNode>,
        contacts: Arc<ContactStore>,
        settings: ChatSettings,
        activity: ChatActivity,
    ) -> Option<Arc<Self>> {
        let (shutdown, _) = watch::channel(false);
        core.set_auto_join(settings.group_auto_join);
        let svc = Arc::new(Self {
            trusted_rate: Mutex::new(Buckets::new(
                settings.inbound_burst,
                settings.inbound_per_minute / 60.0,
            )),
            unverified_rate: Mutex::new(Buckets::new(
                UNVERIFIED_BURST,
                UNVERIFIED_PER_MINUTE / 60.0,
            )),
            unknown: Mutex::new(Buckets::new(5.0, 0.1)),
            core,
            contacts,
            node: node.clone(),
            settings,
            slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            workers: Mutex::new(HashMap::new()),
            shutdown,
            activity,
        });
        node.set_group_handler(Arc::new(Handler(svc.clone())));
        for peer in svc.core.peers_with_work() {
            svc.kick(&peer);
        }
        info!("group chat is on");
        Some(svc)
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        self.core.close();
    }

    pub fn core(&self) -> &Arc<GroupCore> {
        &self.core
    }

    pub fn contacts(&self) -> &Arc<ContactStore> {
        &self.contacts
    }

    /// Whether `id` is a trusted contact: in the contact list and allowed to
    /// write to us.
    pub fn is_trusted(&self, id: &[u8; 32]) -> bool {
        self.contacts
            .by_endpoint(id)
            .is_some_and(|c| c.allow_receive)
    }

    // ── Sending ──────────────────────────────────────────────────────────────

    pub fn kick_all(self: &Arc<Self>, peers: &[[u8; 32]]) {
        for p in peers {
            self.kick(p);
        }
    }

    /// Start or wake the worker of `peer`.
    pub fn kick(self: &Arc<Self>, peer: &[u8; 32]) {
        if *peer == self.core.own_id() {
            return;
        }
        let mut w = self.workers.lock().unwrap();
        if let Some(existing) = w.get(peer) {
            existing.wake.notify_one();
            return;
        }
        let wake = Arc::new(Notify::new());
        w.insert(*peer, Worker { wake: wake.clone() });
        let me = self.clone();
        let peer = *peer;
        tokio::spawn(async move { me.worker(peer, wake).await });
    }

    async fn worker(self: Arc<Self>, peer: [u8; 32], wake: Arc<Notify>) {
        let mut stop = self.shutdown.subscribe();
        let mut conn: Option<Connection> = None;
        let mut failures = 0u32;
        let mut resets = 0u32;
        loop {
            if *stop.borrow() {
                self.workers.lock().unwrap().remove(&peer);
                break;
            }
            // Leave when nothing is owed. Checked under the registry lock so
            // an item queued right now starts a new worker.
            let out = {
                let mut w = self.workers.lock().unwrap();
                match self.core.next_for(&peer) {
                    Some(o) => o,
                    None => {
                        w.remove(&peer);
                        break;
                    }
                }
            };
            match self.attempt(&peer, &out.work, &out.plain, &mut conn).await {
                Outcome::Delivered => {
                    failures = 0;
                    resets = 0;
                    self.core.note_delivery(&peer, None);
                    self.core.delivered(&peer, &out.work);
                }
                Outcome::Skip => {}
                Outcome::Permanent(why) => {
                    failures = 0;
                    debug!(peer = %fingerprint(&peer), "group delivery given up: {why}");
                    self.core.note_delivery(&peer, Some(why));
                    self.core.gave_up(&peer, &out.work);
                }
                Outcome::ResetSession => {
                    resets += 1;
                    self.core.chat().reset_session(&peer);
                    if resets > MAX_RESETS {
                        resets = 0;
                        failures += 1;
                        if self.wait(&wake, &mut stop, failures).await {
                            failures = 0;
                        }
                    }
                }
                Outcome::Retry(why) => {
                    failures += 1;
                    debug!(peer = %fingerprint(&peer), "group delivery waits: {why}");
                    // Some waits are not failures to show the person:
                    // - "peer_busy" is a device that has not joined yet: that
                    //   is the invited state, not a failure to reach it.
                    // - "pqc_pending" is the in-progress hybrid exchange under
                    //   `require` waiting on the member: the body is simply not
                    //   out yet, so nothing is reported until it settles.
                    let transient = matches!(why, "peer_busy" | "pqc_pending");
                    self.core.note_delivery(&peer, (!transient).then_some(why));
                    if self.wait(&wake, &mut stop, failures).await {
                        failures = 0;
                    }
                }
            }
        }
        if let Some(c) = conn {
            c.close(CLOSE_OK.into(), b"done");
        }
    }

    async fn wait(&self, wake: &Notify, stop: &mut watch::Receiver<bool>, failures: u32) -> bool {
        let d = self.settings.delay_after(failures);
        tokio::select! {
            _ = tokio::time::sleep(d) => false,
            _ = wake.notified() => true,
            _ = stop.changed() => false,
        }
    }

    async fn ensure_conn(
        &self,
        slot: &mut Option<Connection>,
        target: &[u8; 32],
    ) -> Result<Connection, IrohClientError> {
        if let Some(c) = slot.as_ref() {
            if c.close_reason().is_none() {
                return Ok(c.clone());
            }
        }
        let c = self.node.connect_alpn(target, GROUP_ALPN).await?;
        *slot = Some(c.clone());
        Ok(c)
    }

    async fn attempt(
        &self,
        peer: &[u8; 32],
        work: &Work,
        plain: &[u8],
        conn_slot: &mut Option<Connection>,
    ) -> Outcome {
        // `work` is read only by the `require` hybrid gate below, which is
        // compiled in only with the `pqc` feature; without it the body is
        // sealed the same way regardless of the item, so mark it used.
        #[cfg(not(feature = "pqc"))]
        let _ = work;
        let _awake = crate::power::ActivityGuard::acquire("Delivering a message");
        // A contact whose sending is switched off gets nothing; the items wait.
        if let Some(c) = self.contacts.by_endpoint(peer) {
            if !c.allow_send {
                return Outcome::Retry("send_disabled");
            }
        }
        let conn = match self.ensure_conn(conn_slot, peer).await {
            Ok(c) => c,
            // Includes a peer whose software has no group chat: the handshake
            // for this ALPN fails there and nothing else is touched.
            Err(e) => return Outcome::Retry(e.reason_code(proto::fail::PEER_NO_GROUP)),
        };
        // Under `require`, a group message body goes out only once the hybrid
        // exchange with this member is established, exactly as for the private
        // chat. The gate drives the exchange and holds, fails or lets the body
        // through; nothing is sealed on the classical session alone.
        #[cfg(feature = "pqc")]
        if let Err(out) = self.pq_gate(peer, work, &conn, conn_slot).await {
            return out;
        }
        let (wire, env_id) = match self.core.chat().seal_for(peer, plain) {
            Ok(w) => w,
            Err(PrepareError::Gone) => return Outcome::Skip,
            Err(PrepareError::Session(_)) => return Outcome::Permanent("session"),
            Err(PrepareError::Storage(_)) => return Outcome::Retry("storage"),
        };
        // Raised while this group send holds the uplink, so the push loop
        // paces itself; dropped as soon as the acknowledgement is in.
        let send_guard = self.activity.enter();
        let result = tokio::time::timeout(self.settings.ack_timeout, async {
            let (mut tx, mut rx) = conn.open_bi().await.map_err(|_| "connection_lost")?;
            proto::write_frame(&mut tx, &Frame::Deliver(wire))
                .await
                .map_err(|_| "connection_lost")?;
            let _ = tx.finish();
            match proto::read_frame(&mut rx).await {
                Ok(Frame::Ack(a)) if a.envelope_id == env_id => Ok(a.status),
                Ok(_) => Err("bad_reply"),
                Err(_) => Err("connection_lost"),
            }
        })
        .await;
        // The uplink is free once the send and its acknowledgement are done.
        drop(send_guard);
        let status = match result {
            Ok(Ok(s)) => s,
            Ok(Err(why)) => {
                if closed_with(&conn, CLOSE_NOT_ALLOWED) {
                    *conn_slot = None;
                    return Outcome::Permanent("not_allowed");
                }
                if closed_with(&conn, CLOSE_UNSUPPORTED) {
                    *conn_slot = None;
                    return Outcome::Permanent("unsupported");
                }
                *conn_slot = None;
                return Outcome::Retry(why);
            }
            Err(_) => {
                *conn_slot = None;
                return Outcome::Retry("timed_out");
            }
        };
        match status {
            AckStatus::Stored | AckStatus::Duplicate => Outcome::Delivered,
            AckStatus::NoSession => Outcome::ResetSession,
            AckStatus::NotAllowed => Outcome::Permanent("not_allowed"),
            AckStatus::TooBig => Outcome::Permanent("too_big"),
            AckStatus::Unsupported => Outcome::Permanent("unsupported"),
            AckStatus::BadRequest => Outcome::Permanent("rejected"),
            AckStatus::Rate => Outcome::Retry("rate_limited"),
            AckStatus::Busy => Outcome::Retry("peer_busy"),
            AckStatus::Failed => Outcome::Retry("peer_failed"),
            AckStatus::Unknown => Outcome::Retry("peer_status_unknown"),
        }
    }

    /// The hybrid-upgrade gate for a group message body under `require`.
    ///
    /// A member's pairwise session carries the same hybrid state as the
    /// private chat, so the rule is the same: a body is sealed on the classical
    /// session only once the hybrid exchange with that member is established.
    /// The hybrid records (offer/kex/confirm) are ordinary pairwise envelopes,
    /// so they travel over the group ALPN and are dispatched by the receiver's
    /// `accept_raw` exactly as on the private ALPN; this worker can therefore
    /// drive the exchange itself for a member it only ever meets in a group.
    ///
    /// Returns `Ok(())` when the body may go (mode is not `require`, the item
    /// is a control record rather than a body, or the exchange is established).
    /// Returns `Err(outcome)` to stop this attempt: a hybrid record was sent
    /// (retry to continue), the exchange is still running (retry), or it
    /// cannot be established and the body is refused (permanent, with the
    /// stated reason the person is shown).
    #[cfg(feature = "pqc")]
    async fn pq_gate(
        &self,
        peer: &[u8; 32],
        work: &Work,
        conn: &Connection,
        conn_slot: &mut Option<Connection>,
    ) -> Result<(), Outcome> {
        use crate::chat::pq::Pass;
        // Only a `require` message *body* is held back for the hybrid exchange.
        // `prefer`/`off`, and every control record under any mode, keep the
        // existing behaviour (the hybrid layer is added if it happens to be
        // ready, and control records flow so the receiver can learn the
        // group's epoch and ask for descriptors). This decision is pure and is
        // unit-tested as `body_is_pqc_gated`.
        if !body_is_pqc_gated(self.settings.pqc_mode, work) {
            return Ok(());
        }
        // Drive every record this side can send in one go, so the worker's
        // failure count is never charged for making progress. The loop only
        // yields back to the worker when it must wait for the member (Hold),
        // when the body may go (Proceed), when the exchange cannot be
        // established (Refuse), or when a record could not be delivered.
        loop {
            match self.core.chat().pq_step(peer, true, now_ms()) {
                Pass::Proceed => return Ok(()),
                // The exchange is still running and the next move is the
                // member's: wait for its record and look again, without
                // charging a failure or showing a reason.
                Pass::Hold => return Err(Outcome::Retry("pqc_pending")),
                Pass::Send(out) => {
                    // Seal and deliver one record, then look again at once for
                    // the next one this side owes (offer, then kex, …).
                    match self.send_pq_record(peer, &out, conn, conn_slot).await {
                        Ok(()) => continue,
                        Err(why) => return Err(Outcome::Retry(why)),
                    }
                }
                Pass::Refuse(refusal) => {
                    // No classical fallback: the body fails on this device with
                    // the stated reason, which the worker records for the
                    // person (through `gave_up`).
                    return Err(Outcome::Permanent(refusal.reason_str()));
                }
            }
        }
    }

    /// Seal one hybrid-upgrade record for `peer` and deliver it over the group
    /// connection, reporting the outcome back to the hybrid state. Mirrors the
    /// private chat's `send_pq`, but on the group ALPN.
    #[cfg(feature = "pqc")]
    async fn send_pq_record(
        &self,
        peer: &[u8; 32],
        out: &crate::chat::pq::Outgoing,
        conn: &Connection,
        conn_slot: &mut Option<Connection>,
    ) -> Result<(), &'static str> {
        use crate::chat::pq::SendOutcome;
        let (wire, env_id) = match self.core.chat().seal_for(peer, &out.plain) {
            Ok(w) => w,
            Err(PrepareError::Gone) => return Err("session"),
            Err(PrepareError::Session(_)) => return Err("session"),
            Err(PrepareError::Storage(_)) => return Err("storage"),
        };
        let send_guard = self.activity.enter();
        let result = tokio::time::timeout(self.settings.ack_timeout, async {
            let (mut tx, mut rx) = conn.open_bi().await.map_err(|_| "connection_lost")?;
            proto::write_frame(&mut tx, &Frame::Deliver(wire))
                .await
                .map_err(|_| "connection_lost")?;
            let _ = tx.finish();
            match proto::read_frame(&mut rx).await {
                Ok(Frame::Ack(a)) if a.envelope_id == env_id => Ok(a.status),
                Ok(_) => Err("bad_reply"),
                Err(_) => Err("connection_lost"),
            }
        })
        .await;
        drop(send_guard);
        let status = match result {
            Ok(Ok(s)) => s,
            Ok(Err(why)) => {
                *conn_slot = None;
                return Err(why);
            }
            Err(_) => {
                *conn_slot = None;
                return Err("timed_out");
            }
        };
        match status {
            AckStatus::Stored | AckStatus::Duplicate => {
                self.core
                    .chat()
                    .pq_sent(peer, out, SendOutcome::Delivered, now_ms());
                Ok(())
            }
            // The member opened the envelope but does not know the record: an
            // older build. The exchange concludes as classical for it.
            AckStatus::BadRequest | AckStatus::Unsupported | AckStatus::TooBig => {
                self.core
                    .chat()
                    .pq_sent(peer, out, SendOutcome::NotUnderstood, now_ms());
                Ok(())
            }
            AckStatus::NoSession => {
                self.core.chat().reset_session(peer);
                Err("no_session")
            }
            AckStatus::NotAllowed => Err("not_allowed"),
            AckStatus::Rate => Err("rate_limited"),
            AckStatus::Busy => Err("peer_busy"),
            AckStatus::Failed => Err("peer_failed"),
            AckStatus::Unknown => Err("peer_status_unknown"),
        }
    }

    // ── Receiving ────────────────────────────────────────────────────────────

    fn may_connect(&self, remote: &[u8; 32]) -> bool {
        self.core.knows(remote) || self.is_trusted(remote)
    }

    async fn serve(self: Arc<Self>, conn: Connection) {
        let remote = *conn.remote_id().as_bytes();
        let Ok(_slot) = self.slots.clone().try_acquire_owned() else {
            conn.close(CLOSE_RATE.into(), b"busy");
            return;
        };
        let mut shutdown = self.shutdown.subscribe();
        let mut bad = 0u32;
        let mut announced = false;
        for _ in 0..MAX_STREAMS_PER_CONNECTION {
            if !self.may_connect(&remote) {
                if self.unknown.lock().unwrap().allow(remote) {
                    debug!(peer = %fingerprint(&remote), "group chat refused: not a member or contact");
                }
                conn.close(CLOSE_NOT_ALLOWED.into(), b"");
                return;
            }
            if !announced {
                announced = true;
                // The member is online: let what we owe it go out now.
                self.kick(&remote);
            }
            let (mut tx, mut rx) = tokio::select! {
                _ = shutdown.changed() => break,
                r = tokio::time::timeout(self.settings.idle_timeout, conn.accept_bi()) => match r {
                    Ok(Ok(s)) => s,
                    _ => break,
                }
            };
            let frame =
                tokio::time::timeout(self.settings.read_timeout, proto::read_frame(&mut rx)).await;
            let wire = match frame {
                Ok(Ok(Frame::Deliver(w))) => w,
                Ok(Err(proto::ProtoError::BadLength(_))) | Ok(Ok(Frame::Ack(_))) => {
                    conn.close(CLOSE_BAD_REQUEST.into(), b"");
                    return;
                }
                _ => break,
            };
            let env_id = envelope_id_of(&wire);
            let trusted = self.is_trusted(&remote);
            let allowed = if trusted {
                self.trusted_rate.lock().unwrap().allow(remote)
            } else {
                self.unverified_rate.lock().unwrap().allow(remote)
            };
            let (status, kick) = if !allowed {
                (AckStatus::Rate, Vec::new())
            } else {
                let core = self.core.clone();
                let contacts = self.contacts.clone();
                match tokio::task::spawn_blocking(move || {
                    let is_trusted =
                        |id: &[u8; 32]| contacts.by_endpoint(id).is_some_and(|c| c.allow_receive);
                    core.accept(&remote, &wire, now_ms(), &is_trusted)
                })
                .await
                {
                    Ok(a) => (a.status, a.kick),
                    Err(_) => (AckStatus::Failed, Vec::new()),
                }
            };
            self.kick_all(&kick);
            let ack = Frame::Ack(Ack {
                status,
                envelope_id: env_id,
            });
            if proto::write_frame(&mut tx, &ack).await.is_err() {
                break;
            }
            let _ = tx.finish();
            match status {
                AckStatus::Unsupported => {
                    let _ = tokio::time::timeout(Duration::from_secs(2), tx.stopped()).await;
                    conn.close(CLOSE_UNSUPPORTED.into(), b"unsupported");
                    return;
                }
                AckStatus::BadRequest => {
                    bad += 1;
                    if bad >= MAX_BAD_IN_A_ROW {
                        let _ = tokio::time::timeout(Duration::from_secs(2), tx.stopped()).await;
                        conn.close(CLOSE_BAD_REQUEST.into(), b"");
                        return;
                    }
                }
                AckStatus::Stored | AckStatus::Duplicate => bad = 0,
                _ => {}
            }
        }
        conn.close(CLOSE_OK.into(), b"done");
    }
}

struct Handler(Arc<GroupService>);

#[async_trait::async_trait]
impl ChatConnectionHandler for Handler {
    async fn handle(&self, conn: Connection) {
        self.0.clone().serve(conn).await
    }
}

/// Whether a group item's *body* must pass the hybrid (`require`) gate before
/// it may be sealed on the classical session.
///
/// This is the group-specific part of the no-silent-downgrade rule, kept pure
/// so it can be unit-tested without a network: a body is gated only when the
/// mode is `require` **and** the item carries a message body. Control records
/// (`Descs`, `Sync`) are never gated — they must flow so a member can learn
/// the group's epoch and ask for descriptors — and `prefer`/`off` never hold a
/// body back. When this returns `true`, `pq_gate` drives the exchange and the
/// body is never sent classically until the exchange is established (or the
/// message is refused); when it returns `false`, delivery proceeds unchanged.
#[cfg(feature = "pqc")]
fn body_is_pqc_gated(mode: crate::config::PqcMode, work: &Work) -> bool {
    use crate::config::PqcMode;
    mode == PqcMode::Require && matches!(work, Work::Text { .. } | Work::Hist { .. })
}

#[cfg(all(test, feature = "pqc"))]
mod pqc_gate_tests {
    use super::body_is_pqc_gated;
    use crate::chat::group::engine::Work;
    use crate::config::PqcMode;

    const TEXT: Work = Work::Text {
        gid: [1u8; 16],
        id: [2u8; 16],
    };
    const HIST: Work = Work::Hist {
        gid: [1u8; 16],
        to: [3u8; 32],
        seq: 1,
    };
    const DESCS: Work = Work::Descs { gid: [1u8; 16] };
    const SYNC: Work = Work::Sync { gid: [1u8; 16] };

    /// Under `require`, only a message body is gated: it is held for the hybrid
    /// exchange and is never sent on the classical session until the exchange
    /// is established. This is the group equivalent of the private-chat
    /// no-classical-fallback rule.
    #[test]
    fn require_gates_a_text_body_so_it_never_goes_out_classical_first() {
        assert!(body_is_pqc_gated(PqcMode::Require, &TEXT));
        assert!(body_is_pqc_gated(PqcMode::Require, &HIST));
    }

    /// Control records are never gated under any mode: they carry no message
    /// body and must flow so the receiver can learn the epoch and request
    /// descriptors. Gating them would stall the group.
    #[test]
    fn control_records_are_never_gated_even_under_require() {
        assert!(!body_is_pqc_gated(PqcMode::Require, &DESCS));
        assert!(!body_is_pqc_gated(PqcMode::Require, &SYNC));
    }

    /// `prefer` and `off` never hold a body back; the hybrid layer is added
    /// only if it happens to be ready. Nothing is gated, including a text body.
    #[test]
    fn prefer_and_off_never_gate_a_body() {
        for mode in [PqcMode::Prefer, PqcMode::Off] {
            assert!(!body_is_pqc_gated(mode, &TEXT));
            assert!(!body_is_pqc_gated(mode, &DESCS));
            assert!(!body_is_pqc_gated(mode, &SYNC));
        }
    }
}
