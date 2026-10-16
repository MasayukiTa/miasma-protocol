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
}

impl GroupService {
    /// Start group chat next to a running chat service and install it as the
    /// handler of the group ALPN.
    pub fn start(chat: &Arc<ChatService>, seed: &[u8; 32], keys: Arc<StateKeys>) -> Option<Arc<Self>> {
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
        Self::start_with(core, chat.node().clone(), chat.contacts().clone(), chat.settings().clone())
    }

    /// As [`start`](Self::start) from parts (tests).
    pub fn start_with(
        core: Arc<GroupCore>,
        node: Arc<IrohNode>,
        contacts: Arc<ContactStore>,
        settings: ChatSettings,
    ) -> Option<Arc<Self>> {
        let (shutdown, _) = watch::channel(false);
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
        self.contacts.by_endpoint(id).is_some_and(|c| c.allow_receive)
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
                    self.core.delivered(&peer, &out.work);
                }
                Outcome::Skip => {}
                Outcome::Permanent(why) => {
                    failures = 0;
                    debug!(peer = %fingerprint(&peer), "group delivery given up: {why}");
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
        _work: &Work,
        plain: &[u8],
        conn_slot: &mut Option<Connection>,
    ) -> Outcome {
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
            Err(_) => return Outcome::Retry("unreachable"),
        };
        let (wire, env_id) = match self.core.chat().seal_for(peer, plain) {
            Ok(w) => w,
            Err(PrepareError::Gone) => return Outcome::Skip,
            Err(PrepareError::Session(_)) => return Outcome::Permanent("session"),
            Err(PrepareError::Storage(_)) => return Outcome::Retry("storage"),
        };
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
