//! The chat service: accepts connections from contacts, delivers the outbox,
//! and answers the IPC.
//!
//! Identity: the only identity of a peer is `Connection::remote_id()`, proven by
//! the QUIC/TLS handshake. Who may send to us is the contact list
//! (`allow_receive`); to whom we may send is `allow_send`. Both are looked up
//! again for every message, so removing or switching off a contact takes effect
//! at once. Anyone else is closed with an application error code and, at debug
//! level only, logged (rate-limited per ID).
//!
//! Delivery: one worker task per contact with queued messages. It dials the
//! contact, seals the oldest message, sends it on a fresh stream and waits for
//! the acknowledgement. A failure keeps the message and waits (5 s, 30 s,
//! 2 min, 10 min, then every 15 min); a connection from that contact wakes the
//! worker at once.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use iroh::endpoint::{Connection, ConnectionError};
use tokio::sync::{watch, Notify, Semaphore};
use tracing::{debug, info, warn};

use super::{
    crypto::Identity,
    engine::{now_ms, ChatCore, EnqueueError, MarkOutcome, PrepareError},
    outbox::{OutKind, Outbox},
    proto::{
        self, fail, Ack, AckStatus, Frame, CLOSE_BAD_REQUEST, CLOSE_NOT_ALLOWED, CLOSE_OK,
        CLOSE_RATE, CLOSE_UNSUPPORTED,
    },
    store::{ChatStore, StoreSettings},
    sync,
};
use crate::{
    config::{NodeConfig, PqcMode},
    push::{
        contact::fingerprint,
        store::{Contact, ContactStore},
    },
    state_crypto::StateKeys,
    transport::iroh_direct::{ChatConnectionHandler, IrohClientError, IrohNode, CHAT_ALPN},
};

/// Streams (messages) served on one connection before it is closed.
const MAX_STREAMS_PER_CONNECTION: usize = 10_000;
/// Chat connections served at once.
const MAX_CONNECTIONS: usize = 8;
/// A peer that sends this many bad messages in a row is disconnected.
const MAX_BAD_IN_A_ROW: u32 = 3;
/// Sessions restarted in a row for one message before it waits.
const MAX_RESETS: u32 = 2;
/// How long a contact that did not understand `Sync` is left alone before it
/// is asked again (it may have been updated meanwhile).
const SYNC_RETRY_AFTER: Duration = Duration::from_secs(3600);
/// Contacts remembered as not understanding `Sync`.
const MAX_NO_SYNC: usize = 256;
/// How long a new connection waits for the answer to `Sync`.
const SYNC_WAIT: Duration = Duration::from_secs(5);

/// Runtime settings.
#[derive(Clone)]
pub struct ChatSettings {
    pub max_message_bytes: usize,
    /// Waits after the 1st, 2nd, ... failed attempt; then [`retry_every`](Self::retry_every).
    pub retry_delays: Vec<Duration>,
    pub retry_every: Duration,
    /// Plus or minus this fraction of random variation on each wait.
    pub retry_jitter: f64,
    pub idle_timeout: Duration,
    pub read_timeout: Duration,
    pub ack_timeout: Duration,
    /// Messages accepted from one contact: burst and per minute.
    pub inbound_burst: f64,
    pub inbound_per_minute: f64,
    /// Join a group at once when a trusted administrator adds us (`chat.group_auto_join`).
    pub group_auto_join: bool,
    /// `privacy.pqc_mode`. Only builds with the `pqc` feature act on it.
    pub pqc_mode: PqcMode,
    /// Where the record of the last session files written is kept, outside
    /// the data folder. `None` keeps only marks in memory.
    pub anchor_dir: Option<PathBuf>,
}

impl Default for ChatSettings {
    fn default() -> Self {
        Self {
            max_message_bytes: proto::MAX_TEXT_BYTES,
            retry_delays: vec![
                Duration::from_secs(5),
                Duration::from_secs(30),
                Duration::from_secs(120),
                Duration::from_secs(600),
            ],
            retry_every: Duration::from_secs(900),
            retry_jitter: 0.2,
            idle_timeout: Duration::from_secs(60),
            read_timeout: Duration::from_secs(30),
            ack_timeout: Duration::from_secs(30),
            inbound_burst: 20.0,
            inbound_per_minute: 30.0,
            group_auto_join: true,
            pqc_mode: PqcMode::Off,
            anchor_dir: None,
        }
    }
}

impl ChatSettings {
    /// The wait after `failures` failed attempts in a row (1-based).
    pub fn delay_after(&self, failures: u32) -> Duration {
        let base = match self.retry_delays.get(failures.saturating_sub(1) as usize) {
            Some(d) => *d,
            None => self.retry_every,
        };
        if self.retry_jitter <= 0.0 {
            return base;
        }
        let f = 1.0 + self.retry_jitter * (rand::random::<f64>() * 2.0 - 1.0);
        base.mul_f64(f.max(0.0))
    }
}

/// Token bucket per ID with bounded memory.
pub(crate) struct Buckets {
    map: HashMap<[u8; 32], (f64, Instant)>,
    burst: f64,
    per_sec: f64,
}

impl Buckets {
    const CAP: usize = 1024;

    pub(crate) fn new(burst: f64, per_sec: f64) -> Self {
        Self {
            map: HashMap::new(),
            burst,
            per_sec,
        }
    }

    pub(crate) fn allow(&mut self, id: [u8; 32]) -> bool {
        let now = Instant::now();
        if self.map.len() >= Self::CAP && !self.map.contains_key(&id) {
            let mut v: Vec<_> = self.map.iter().map(|(k, (_, t))| (*t, *k)).collect();
            v.sort();
            for (_, k) in v.into_iter().take(Self::CAP / 4) {
                self.map.remove(&k);
            }
        }
        let e = self.map.entry(id).or_insert((self.burst, now));
        let dt = now.duration_since(e.1).as_secs_f64();
        e.0 = (e.0 + dt * self.per_sec).min(self.burst);
        e.1 = now;
        if e.0 >= 1.0 {
            e.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

// ─── Registry (one service per data dir) ─────────────────────────────────────

static SERVICES: OnceLock<Mutex<HashMap<PathBuf, Arc<ChatService>>>> = OnceLock::new();

fn services() -> &'static Mutex<HashMap<PathBuf, Arc<ChatService>>> {
    SERVICES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The chat service of the daemon that owns `data_dir`, if it runs one.
pub fn service_for(data_dir: &Path) -> Option<Arc<ChatService>> {
    services().lock().unwrap().get(data_dir).cloned()
}

pub fn unregister_service(data_dir: &Path) {
    if let Some(s) = services().lock().unwrap().remove(data_dir) {
        s.shutdown();
    }
}

/// Start chat for the daemon of `data_dir` (reads `[chat]` and `[privacy]`
/// from `config.toml`). `seed` is the Ed25519 seed the iroh endpoint uses.
/// Returns `None` when chat is switched off or its state cannot be opened.
pub fn start_for_daemon(
    data_dir: &Path,
    node: Arc<IrohNode>,
    seed: &[u8; 32],
    contacts: Arc<ContactStore>,
) -> Option<Arc<ChatService>> {
    let cfg = NodeConfig::load(data_dir).unwrap_or_default();
    if !cfg.chat.enabled {
        info!("chat is off (chat.enabled = false)");
        return None;
    }
    let keys = match StateKeys::open_or_init(data_dir) {
        Ok(k) => Arc::new(k),
        Err(e) => {
            warn!("chat stays off: {e}");
            return None;
        }
    };
    let mut store = StoreSettings {
        history_save: cfg.chat.history_saved(),
        retention_days: cfg.chat.retention_days,
        ..StoreSettings::default()
    };
    store.outbox_max = cfg.chat.outbox_max.clamp(1, 500);
    let settings = ChatSettings {
        max_message_bytes: cfg.chat.max_message_bytes.clamp(1, proto::MAX_TEXT_BYTES),
        group_auto_join: cfg.chat.group_auto_join,
        pqc_mode: cfg.privacy.pqc_mode,
        anchor_dir: crate::paths::anchor_dir(data_dir),
        ..ChatSettings::default()
    };
    if cfg.privacy.pqc_mode != PqcMode::Off && !PqcMode::available() {
        // Said once, plainly: the setting is on but this build cannot do it.
        warn!(
            "privacy.pqc_mode is {} but this build has no advanced encryption; \
             private conversations stay standard",
            cfg.privacy.pqc_mode
        );
    }
    let svc = ChatService::start(
        &crate::paths::chat_dir(data_dir),
        node,
        seed,
        keys,
        contacts,
        store,
        settings,
    )?;
    svc.core().set_receipts_global(cfg.chat.read_receipts);
    services()
        .lock()
        .unwrap()
        .insert(data_dir.to_path_buf(), svc.clone());
    Some(svc)
}

// ─── The service ─────────────────────────────────────────────────────────────

struct Worker {
    wake: Arc<Notify>,
}

pub struct ChatService {
    core: Arc<ChatCore>,
    contacts: Arc<ContactStore>,
    node: Arc<IrohNode>,
    settings: ChatSettings,
    unknown: Mutex<Buckets>,
    inbound_rate: Mutex<Buckets>,
    sync_rate: Mutex<Buckets>,
    /// Contacts that did not answer a `Sync` (older builds).
    no_sync: Mutex<HashMap<[u8; 32], Instant>>,
    /// Contacts whose build answered a read receipt with "bad request" (it
    /// predates receipts): none are sent to them for a while.
    no_receipts: Mutex<HashMap<[u8; 32], Instant>>,
    slots: Arc<Semaphore>,
    workers: Mutex<HashMap<[u8; 32], Worker>>,
    shutdown: watch::Sender<bool>,
    groups: OnceLock<Arc<super::group::service::GroupService>>,
}

impl ChatService {
    /// Create the service and install it as the CHAT_ALPN handler of `node`.
    pub fn start(
        chat_dir: &Path,
        node: Arc<IrohNode>,
        seed: &[u8; 32],
        keys: Arc<StateKeys>,
        contacts: Arc<ContactStore>,
        store_settings: StoreSettings,
        settings: ChatSettings,
    ) -> Option<Arc<Self>> {
        let identity = Identity::from_seed(seed);
        if identity.id() != node.endpoint_id() {
            warn!("chat stays off: its identity differs from the endpoint's");
            return None;
        }
        let store = match ChatStore::open(
            chat_dir,
            keys.clone(),
            identity.id(),
            store_settings.clone(),
        ) {
            Ok(s) => s.with_anchor(super::anchor::Anchor::new(
                settings.anchor_dir.clone(),
                keys.clone(),
                identity.id(),
            )),
            Err(e) => {
                warn!("chat stays off: {e}");
                return None;
            }
        };
        let (outbox, expired) = Outbox::open(
            &crate::paths::chat_outbox_file(chat_dir),
            keys.clone(),
            store_settings,
            now_ms(),
        );
        let core = Arc::new(ChatCore::new(
            store,
            outbox,
            identity,
            settings.max_message_bytes,
        ));
        #[cfg(feature = "pqc")]
        core.set_pqc_mode(settings.pqc_mode);
        let now = now_ms();
        for e in expired {
            // Recorded as failed so the person sees what did not go out.
            core.record_unsent(&e, fail::EXPIRED, now);
        }
        let (shutdown, _) = watch::channel(false);
        let svc = Arc::new(Self {
            core,
            contacts,
            node: node.clone(),
            unknown: Mutex::new(Buckets::new(5.0, 0.1)),
            inbound_rate: Mutex::new(Buckets::new(
                settings.inbound_burst,
                settings.inbound_per_minute / 60.0,
            )),
            sync_rate: Mutex::new(Buckets::new(4.0, 6.0 / 60.0)),
            no_sync: Mutex::new(HashMap::new()),
            no_receipts: Mutex::new(HashMap::new()),
            settings,
            slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            workers: Mutex::new(HashMap::new()),
            shutdown,
            groups: OnceLock::new(),
        });
        node.set_chat_handler(Arc::new(Handler(svc.clone())));
        if let Some(g) = super::group::service::GroupService::start(&svc, seed, keys) {
            let _ = svc.groups.set(g);
        }
        // Whatever was waiting when the program last stopped.
        for peer in svc.core.outbox.peers() {
            svc.kick(&peer);
        }
        {
            let me = svc.clone();
            let mut stop = svc.shutdown.subscribe();
            tokio::spawn(async move {
                loop {
                    let n = me.core.store.sweep_retention(now_ms());
                    if n > 0 {
                        info!("removed {n} chat message(s) older than the retention");
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(24 * 3600)) => {}
                        _ = stop.changed() => return,
                    }
                }
            });
        }
        info!("chat is on");
        Some(svc)
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        if let Some(g) = self.groups.get() {
            g.shutdown();
        }
        self.core.store.close();
        // The hybrid session keys leave memory with the service.
        #[cfg(feature = "pqc")]
        self.core.pq.clear_memory();
    }

    pub fn core(&self) -> &Arc<ChatCore> {
        &self.core
    }

    pub fn node(&self) -> &Arc<IrohNode> {
        &self.node
    }

    /// Group chat, which runs on the same endpoint and identity.
    pub fn groups(&self) -> Option<&Arc<super::group::service::GroupService>> {
        self.groups.get()
    }

    pub fn contacts(&self) -> &Arc<ContactStore> {
        &self.contacts
    }

    pub fn settings(&self) -> &ChatSettings {
        &self.settings
    }

    pub fn own_endpoint_id(&self) -> [u8; 32] {
        self.core.own_id()
    }

    // ── Sending ──────────────────────────────────────────────────────────────

    /// Queue `text` for a contact. Returns the message ID.
    pub fn send(self: &Arc<Self>, contact: &Contact, text: &str) -> Result<[u8; 16], EnqueueError> {
        let peer = contact
            .endpoint_bytes()
            .ok_or_else(|| EnqueueError::Storage("bad contact".into()))?;
        let id = self.core.enqueue(&peer, text, now_ms())?;
        self.kick(&peer);
        Ok(id)
    }

    /// The person is looking at the conversation with `contact` and has seen
    /// the messages received up to number `up_to`: queue a read receipt when
    /// receipts are on.
    pub fn mark_read(
        self: &Arc<Self>,
        contact: &Contact,
        up_to: u64,
    ) -> Result<MarkOutcome, super::store::StoreError> {
        let peer = contact
            .endpoint_bytes()
            .ok_or(super::store::StoreError::Damaged)?;
        let out = self.core.mark_read(&peer, up_to, now_ms())?;
        if out == MarkOutcome::Queued && contact.allow_send {
            self.kick(&peer);
        }
        Ok(out)
    }

    /// Start or wake the worker of `peer`: it tries its queue at once.
    pub fn kick(self: &Arc<Self>, peer: &[u8; 32]) {
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
        // The message for which a refusal already led to a new session.
        let mut restarted_for: Option<[u8; 16]> = None;
        loop {
            if *stop.borrow() {
                self.workers.lock().unwrap().remove(&peer);
                break;
            }
            // The opt-in hybrid upgrade goes first: its records, and under
            // `require` the decision whether a message may go at all.
            #[cfg(feature = "pqc")]
            match self
                .pq_pass(&peer, &mut conn, &wake, &mut stop, &mut failures)
                .await
            {
                PqLoop::Free => {}
                PqLoop::Again => continue,
                PqLoop::Leave => {
                    // Checked under the registry lock: a message queued
                    // right now keeps this worker.
                    let mut w = self.workers.lock().unwrap();
                    if self.core.outbox.first_for(&peer).is_none() {
                        w.remove(&peer);
                        break;
                    }
                }
            }
            // Leave when nothing is waiting. Checked under the registry lock
            // so a message queued right now starts a new worker.
            let entry = {
                let mut w = self.workers.lock().unwrap();
                match self.core.outbox.first_for(&peer) {
                    Some(e) => e,
                    None => {
                        w.remove(&peer);
                        break;
                    }
                }
            };
            // A read receipt is only worth sending soon: past its expiry it
            // is dropped, quietly (it never reaches the history).
            if self.core.receipt_expired(&entry, now_ms()) {
                self.core.outbox.remove(&entry.id);
                continue;
            }
            // A contact on a build from before read receipts answers each one
            // with "bad request": stop sending them (quietly, as for an
            // expired one) until it is asked again after an hour.
            if entry.kind == OutKind::Read && self.peer_lacks_receipts(&peer) {
                self.core.outbox.remove(&entry.id);
                continue;
            }
            self.core
                .outbox
                .update(&entry.id, |e| e.last_try_ms = now_ms());
            match self.attempt(&peer, &entry.id, &mut conn).await {
                Outcome::Delivered => {
                    failures = 0;
                    resets = 0;
                    self.core.mark_delivered(&entry.id, now_ms());
                }
                Outcome::Gone => {}
                Outcome::Permanent(reason) => {
                    failures = 0;
                    self.core.mark_failed(&entry.id, reason, now_ms());
                }
                Outcome::Rejected => {
                    // A build from before `NoSession` was answered for state
                    // that does not match answers "bad request" instead: start
                    // a new session once for this message, then take the
                    // answer as it is.
                    if restarted_for == Some(entry.id) {
                        failures = 0;
                        self.core.mark_failed(&entry.id, fail::REJECTED, now_ms());
                    } else {
                        restarted_for = Some(entry.id);
                        self.core.reset_session(&peer);
                    }
                }
                Outcome::ResetSession => {
                    resets += 1;
                    self.core.reset_session(&peer);
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
                    debug!(peer = %fingerprint(&peer), "chat delivery waits: {why}");
                    self.core.outbox.update(&entry.id, |e| {
                        e.sending = false;
                        e.attempts += 1;
                        e.last_error = Some(why.to_owned());
                    });
                    // A wake means the contact is here: start the schedule over.
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

    /// Wait out the delay of the schedule, or until the worker is woken.
    async fn wait(&self, wake: &Notify, stop: &mut watch::Receiver<bool>, failures: u32) -> bool {
        let d = self.settings.delay_after(failures);
        tokio::select! {
            _ = tokio::time::sleep(d) => false,
            _ = wake.notified() => true,
            _ = stop.changed() => false,
        }
    }

    /// The open connection, or a new one; the flag is true for a new one.
    async fn ensure_conn(
        &self,
        slot: &mut Option<Connection>,
        target: &[u8; 32],
    ) -> Result<(Connection, bool), IrohClientError> {
        if let Some(c) = slot.as_ref() {
            if c.close_reason().is_none() {
                return Ok((c.clone(), false));
            }
        }
        let c = self.node.connect_alpn(target, CHAT_ALPN).await?;
        *slot = Some(c.clone());
        Ok((c, true))
    }

    fn peer_lacks_sync(&self, peer: &[u8; 32]) -> bool {
        let mut m = self.no_sync.lock().unwrap();
        match m.get(peer) {
            Some(t) if t.elapsed() < SYNC_RETRY_AFTER => true,
            Some(_) => {
                m.remove(peer);
                false
            }
            None => false,
        }
    }

    fn peer_lacks_receipts(&self, peer: &[u8; 32]) -> bool {
        let mut m = self.no_receipts.lock().unwrap();
        match m.get(peer) {
            Some(t) if t.elapsed() < SYNC_RETRY_AFTER => true,
            Some(_) => {
                m.remove(peer);
                false
            }
            None => false,
        }
    }

    fn note_no_receipts(&self, peer: &[u8; 32]) {
        let mut m = self.no_receipts.lock().unwrap();
        if m.len() >= MAX_NO_SYNC && !m.contains_key(peer) {
            m.clear();
        }
        m.insert(*peer, Instant::now());
    }

    fn note_no_sync(&self, peer: &[u8; 32]) {
        let mut m = self.no_sync.lock().unwrap();
        if m.len() >= MAX_NO_SYNC && !m.contains_key(peer) {
            m.clear();
        }
        m.insert(*peer, Instant::now());
    }

    /// Ask the contact which of our waiting messages it already has and close
    /// those. `Ok(n)` is the number closed; `Err` is the reason the exchange
    /// failed ("no_answer" while the link is up means an older build).
    async fn sync_with(&self, conn: &Connection, peer: &[u8; 32]) -> Result<usize, &'static str> {
        let core = self.core.clone();
        let p = *peer;
        let asked = tokio::task::spawn_blocking(move || sync::request_for(&core, &p))
            .await
            .map_err(|_| "storage")?;
        if asked.is_empty() {
            return Ok(0);
        }
        // Sent on a unidirectional stream: a build from before `Sync` only
        // ever accepts bidirectional streams, so it leaves this one unread and
        // the connection stays up; the answer is simply missing.
        let wait = self.settings.ack_timeout.min(SYNC_WAIT);
        let reply = tokio::time::timeout(wait, async {
            let mut tx = conn.open_uni().await.map_err(|_| "connection_lost")?;
            proto::write_frame(&mut tx, &Frame::Sync(asked.clone()))
                .await
                .map_err(|_| "connection_lost")?;
            let _ = tx.finish();
            let mut rx = conn.accept_uni().await.map_err(|_| "connection_lost")?;
            match proto::read_frame(&mut rx).await {
                Ok(Frame::SyncReply(ids)) => Ok(ids),
                Ok(_) => Err("bad_reply"),
                // A frame that arrived but is not one we read (a build with
                // a different catch-up) is "no usable answer", not a dead link.
                Err(proto::ProtoError::Io(_)) => Err("connection_lost"),
                Err(_) => Err("bad_reply"),
            }
        })
        .await
        .map_err(|_| "no_answer")??;
        let core = self.core.clone();
        let p = *peer;
        tokio::task::spawn_blocking(move || sync::apply_reply(&core, &p, &asked, &reply, now_ms()))
            .await
            .map_err(|_| "storage")
    }

    async fn attempt(
        &self,
        peer: &[u8; 32],
        id: &[u8; 16],
        conn_slot: &mut Option<Connection>,
    ) -> Outcome {
        // Held while one delivery attempt (dial, send, wait for the ack) runs.
        let _awake = crate::power::ActivityGuard::acquire("Delivering a message");
        // Permission is read again for every attempt.
        match self.contacts.by_endpoint(peer) {
            None => return Outcome::Permanent(fail::CONTACT_REMOVED),
            Some(c) if !c.allow_send => return Outcome::Permanent(fail::SEND_DISABLED),
            Some(_) => {}
        }
        let (conn, fresh) = match self.ensure_conn(conn_slot, peer).await {
            Ok(c) => c,
            // Why, in a word the person can be shown: no route found, the
            // handshake failed, or the contact's build has no chat at all.
            Err(e) => return Outcome::Retry(e.reason_code(fail::PEER_NO_CHAT)),
        };
        // A new connection starts with the catch-up: whatever the contact has
        // already applied is closed here instead of being sent again.
        if fresh && !self.peer_lacks_sync(peer) {
            match self.sync_with(&conn, peer).await {
                Ok(n) => {
                    if n > 0 {
                        debug!(peer = %fingerprint(peer), "chat sync closed {n} message(s)");
                    }
                    if self.core.outbox.get(id).is_none() {
                        return Outcome::Gone;
                    }
                }
                Err("no_answer" | "bad_reply") if conn.close_reason().is_none() => {
                    // Nobody answered and the link is fine: a build from
                    // before `Sync`. Send on this connection as usual.
                    self.note_no_sync(peer);
                }
                Err(why) => {
                    *conn_slot = None;
                    if closed_with(&conn, CLOSE_NOT_ALLOWED) {
                        return Outcome::Permanent(fail::NOT_ALLOWED);
                    }
                    return Outcome::Retry(why);
                }
            }
        }
        let (wire, env_id) = match self.core.prepare_wire(id) {
            Ok(w) => w,
            Err(PrepareError::Gone) => return Outcome::Gone,
            Err(PrepareError::Session(_)) => return Outcome::Permanent(fail::SESSION),
            Err(PrepareError::Storage(_)) => return Outcome::Retry("storage"),
        };
        self.core.outbox.update(id, |e| e.sending = true);
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
                    return Outcome::Permanent(fail::NOT_ALLOWED);
                }
                if closed_with(&conn, CLOSE_UNSUPPORTED) {
                    *conn_slot = None;
                    return Outcome::Permanent(fail::UNSUPPORTED);
                }
                *conn_slot = None;
                return Outcome::Retry(why);
            }
            Err(_) => {
                *conn_slot = None;
                return Outcome::Retry("timed_out");
            }
        };
        let is_receipt = self
            .core
            .outbox
            .get(id)
            .is_some_and(|e| e.kind == OutKind::Read);
        match status {
            AckStatus::BadRequest if is_receipt => {
                // The record opened on the other side but was not understood:
                // a build from before read receipts. Drop this one and send
                // no more to it for a while; nothing is shown as failed.
                self.note_no_receipts(peer);
                Outcome::Permanent(fail::REJECTED)
            }
            AckStatus::Unknown => Outcome::Retry("peer_status_unknown"),
            AckStatus::Stored | AckStatus::Duplicate => Outcome::Delivered,
            AckStatus::NoSession => Outcome::ResetSession,
            AckStatus::NotAllowed => Outcome::Permanent(fail::NOT_ALLOWED),
            AckStatus::TooBig => Outcome::Permanent(fail::TOO_BIG),
            AckStatus::Unsupported => Outcome::Permanent(fail::UNSUPPORTED),
            AckStatus::BadRequest => Outcome::Rejected,
            AckStatus::Rate => Outcome::Retry("rate_limited"),
            AckStatus::Busy => Outcome::Retry("peer_busy"),
            AckStatus::Failed => Outcome::Retry("peer_failed"),
        }
    }

    // ── Receiving ────────────────────────────────────────────────────────────

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
            // Looked up for every stream: a contact removed or switched off
            // mid-connection stops being served at once.
            match self.contacts.by_endpoint(&remote) {
                Some(c) if c.allow_receive => {}
                _ => {
                    self.contacts.note_unknown(&remote);
                    let loud = self.unknown.lock().unwrap().allow(remote);
                    if loud {
                        debug!(peer = %fingerprint(&remote), "chat refused: not a contact that may write");
                    }
                    conn.close(CLOSE_NOT_ALLOWED.into(), b"");
                    return;
                }
            }
            if !announced {
                announced = true;
                // The contact is online: let our own queue for it go out now.
                self.kick(&remote);
            }
            let (mut tx, mut rx) = tokio::select! {
                _ = shutdown.changed() => break,
                u = conn.accept_uni() => {
                    // `Sync` arrives on a unidirectional stream (see
                    // `sync_with`); the answer goes back on one of ours.
                    let Ok(mut urx) = u else { break };
                    let frame = tokio::time::timeout(
                        self.settings.read_timeout,
                        proto::read_frame(&mut urx),
                    )
                    .await;
                    let items = match frame {
                        Ok(Ok(Frame::Sync(items))) => items,
                        // A unidirectional frame this build does not know
                        // (or an old-shaped one): it is not answered, and the
                        // connection stays up for the messages on it. The
                        // sender stops waiting for the answer by itself.
                        Ok(Ok(_)) | Ok(Err(proto::ProtoError::BadType(_)))
                        | Ok(Err(proto::ProtoError::Malformed(_))) => continue,
                        _ => {
                            conn.close(CLOSE_BAD_REQUEST.into(), b"");
                            return;
                        }
                    };
                    // Which of the sender's waiting messages we have already.
                    let have = if self.sync_rate.lock().unwrap().allow(remote) {
                        let core = self.core.clone();
                        tokio::task::spawn_blocking(move || sync::answer(&core, &remote, &items))
                            .await
                            .unwrap_or_default()
                    } else {
                        // Too many catch-ups: an empty answer only makes the
                        // sender send everything (duplicates are harmless).
                        Vec::new()
                    };
                    let Ok(mut utx) = conn.open_uni().await else { break };
                    if proto::write_frame(&mut utx, &Frame::SyncReply(have)).await.is_err() {
                        break;
                    }
                    let _ = utx.finish();
                    continue;
                }
                r = tokio::time::timeout(self.settings.idle_timeout, conn.accept_bi()) => match r {
                    Ok(Ok(s)) => s,
                    _ => break,
                }
            };
            let frame =
                tokio::time::timeout(self.settings.read_timeout, proto::read_frame(&mut rx)).await;
            let wire = match frame {
                Ok(Ok(Frame::Deliver(w))) => w,
                Ok(Err(proto::ProtoError::BadLength(_)))
                | Ok(Ok(Frame::Ack(_)))
                | Ok(Ok(Frame::Sync(_)))
                | Ok(Ok(Frame::SyncReply(_))) => {
                    conn.close(CLOSE_BAD_REQUEST.into(), b"");
                    return;
                }
                // A frame type from a newer build: tell it so (it can send the
                // old form) instead of dropping the connection unexplained.
                Ok(Err(proto::ProtoError::BadType(_))) => {
                    conn.close(CLOSE_UNSUPPORTED.into(), b"unsupported");
                    return;
                }
                _ => break,
            };
            let env_id = envelope_id_of(&wire);
            let status = if !self.inbound_rate.lock().unwrap().allow(remote) {
                AckStatus::Rate
            } else {
                let core = self.core.clone();
                let w = wire;
                // Cipher and disk work off the async threads.
                match tokio::task::spawn_blocking(move || core.accept(&remote, &w, now_ms())).await
                {
                    Ok(o) => o.status,
                    Err(_) => AckStatus::Failed,
                }
            };
            let ack = Frame::Ack(Ack {
                status,
                envelope_id: env_id,
            });
            if proto::write_frame(&mut tx, &ack).await.is_err() {
                break;
            }
            let _ = tx.finish();
            // A record of the hybrid upgrade may owe an answer: wake the
            // delivery loop for this contact.
            #[cfg(feature = "pqc")]
            if status == AckStatus::Stored && self.core.pq_attention(&remote, now_ms()) {
                self.kick(&remote);
            }
            match status {
                AckStatus::Unsupported => {
                    // Let the answer reach the peer, then end politely.
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

// ─── Hybrid upgrade (opt-in, `pqc` feature) ──────────────────────────────────

/// What the worker does after the hybrid-upgrade step.
#[cfg(feature = "pqc")]
enum PqLoop {
    /// Nothing more to do here: go on with the messages.
    Free,
    /// Something happened (a record went out, a message was failed, a wait
    /// ended): look again from the top.
    Again,
    /// Nothing waits and the contact cannot be reached: end this worker.
    Leave,
}

/// How often a held message asks again whether the exchange is finished.
#[cfg(feature = "pqc")]
const PQ_POLL: Duration = Duration::from_secs(2);
/// Longest single wait for a time-driven decision (it asks again afterwards).
#[cfg(feature = "pqc")]
const PQ_DEADLINE_CAP_MS: u64 = 20_000;
/// Failures in a row after which a worker that has only hybrid-upgrade
/// records to send ends (the next message or record from the contact starts it
/// again).
#[cfg(feature = "pqc")]
const PQ_ONLY_RETRIES: u32 = 3;

#[cfg(feature = "pqc")]
impl ChatService {
    /// The hybrid-upgrade step of the delivery loop of `peer`.
    async fn pq_pass(
        &self,
        peer: &[u8; 32],
        conn_slot: &mut Option<Connection>,
        wake: &Notify,
        stop: &mut watch::Receiver<bool>,
        failures: &mut u32,
    ) -> PqLoop {
        use super::pq::Pass;
        if self.settings.pqc_mode == PqcMode::Off {
            return PqLoop::Free;
        }
        // Only contacts we may write to.
        match self.contacts.by_endpoint(peer) {
            Some(c) if c.allow_send => {}
            _ => return PqLoop::Free,
        }
        let first = self.core.outbox.first_for(peer);
        let have_text = first.is_some();
        match self.core.pq_step(peer, have_text, now_ms()) {
            Pass::Proceed => {
                // Nothing waits, but the wait for the contact's offer is still
                // running: stay until it is over (or something arrives), so
                // the conversation is shown as classical only without a
                // further message.
                if !have_text {
                    if let Some(ms) = self.core.pq_deadline(peer, now_ms()) {
                        let d = Duration::from_millis(ms.min(PQ_DEADLINE_CAP_MS));
                        tokio::select! {
                            _ = tokio::time::sleep(d) => {}
                            _ = wake.notified() => {}
                            _ = stop.changed() => {}
                        }
                        return PqLoop::Again;
                    }
                }
                PqLoop::Free
            }
            Pass::Hold => {
                tokio::select! {
                    _ = tokio::time::sleep(PQ_POLL) => {}
                    _ = wake.notified() => {}
                    _ = stop.changed() => {}
                }
                PqLoop::Again
            }
            Pass::Refuse(reason) => {
                // `require`: nothing goes out in the classical session. The
                // message stays in the history as failed, with the reason.
                if let Some(e) = first {
                    self.core.mark_failed(&e.id, reason, now_ms());
                }
                PqLoop::Again
            }
            Pass::Send(out) => match self.send_pq(peer, &out, conn_slot).await {
                Ok(()) => {
                    *failures = 0;
                    PqLoop::Again
                }
                Err(why) => {
                    *failures += 1;
                    debug!(peer = %fingerprint(peer), "hybrid upgrade waits: {why}");
                    if !have_text && *failures >= PQ_ONLY_RETRIES {
                        return PqLoop::Leave;
                    }
                    if self.wait(wake, stop, *failures).await {
                        *failures = 0;
                    }
                    PqLoop::Again
                }
            },
        }
    }

    /// Seal one hybrid-upgrade record and deliver it like a message.
    async fn send_pq(
        &self,
        peer: &[u8; 32],
        out: &super::pq::Outgoing,
        conn_slot: &mut Option<Connection>,
    ) -> Result<(), &'static str> {
        use super::pq::SendOutcome;
        let (conn, _) = self
            .ensure_conn(conn_slot, peer)
            .await
            .map_err(|e| e.reason_code(fail::PEER_NO_CHAT))?;
        let (wire, env_id) = self.core.seal_for(peer, &out.plain).map_err(|e| match e {
            PrepareError::Storage(_) => "storage",
            _ => "session",
        })?;
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
                    .pq_sent(peer, out, SendOutcome::Delivered, now_ms());
                Ok(())
            }
            // The peer opened the envelope and does not know the record: an
            // older build. Nothing else changed, messages go on as before.
            AckStatus::BadRequest | AckStatus::Unsupported | AckStatus::TooBig => {
                self.core
                    .pq_sent(peer, out, SendOutcome::NotUnderstood, now_ms());
                Ok(())
            }
            AckStatus::NoSession => {
                self.core.reset_session(peer);
                Err("no_session")
            }
            AckStatus::NotAllowed => Err("not_allowed"),
            AckStatus::Rate => Err("rate_limited"),
            AckStatus::Busy => Err("peer_busy"),
            AckStatus::Failed => Err("peer_failed"),
            AckStatus::Unknown => Err("peer_status_unknown"),
        }
    }
}

/// What the endpoint calls for a chat connection.
struct Handler(Arc<ChatService>);

#[async_trait::async_trait]
impl ChatConnectionHandler for Handler {
    async fn handle(&self, conn: Connection) {
        self.0.clone().serve(conn).await
    }
}

enum Outcome {
    Delivered,
    /// The entry was removed (cancelled) while we were about to send it.
    Gone,
    Permanent(&'static str),
    Retry(&'static str),
    ResetSession,
    /// The contact answered "bad request" to a text.
    Rejected,
}

pub(crate) fn closed_with(conn: &Connection, code: u32) -> bool {
    matches!(
        conn.close_reason(),
        Some(ConnectionError::ApplicationClosed(c)) if u64::from(c.error_code) == u64::from(code)
    )
}

/// The envelope ID at its fixed place in the bytes (3 bytes in), or zeros when
/// the bytes are too short to hold one (the ack then carries no useful ID).
pub(crate) fn envelope_id_of(wire: &[u8]) -> [u8; 16] {
    wire.get(3..19)
        .and_then(|s| <[u8; 16]>::try_from(s).ok())
        .unwrap_or_else(rand::random)
}
