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
use tokio::io::AsyncReadExt;
use tokio::sync::{watch, Notify, Semaphore};
use tracing::{debug, info, warn};

#[cfg(feature = "pqc")]
#[path = "call/immediate.rs"]
mod immediate;
#[cfg(feature = "pqc")]
pub use immediate::{CallControlError, CALL_CONTROL_SEND_TTL_MS};

use super::{
    activity::ChatActivity,
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
    chat::mailbox::holder::CustodyStore as _,
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
    /// Hold sealed messages for trusted contacts who are offline, and leave a
    /// copy with trusted holders when a direct send cannot go through
    /// (`chat.custody_enabled`, default off).
    pub custody_enabled: bool,
    /// How many trusted holders get a copy when a direct send fails
    /// (`chat.custody_copies`, 1-8).
    pub custody_copies: usize,
    /// How often the collection task asks our trusted holders for anything
    /// kept for us. It also runs when woken by a fresh inbound connection.
    pub custody_collect_every: Duration,
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
            custody_enabled: false,
            custody_copies: crate::config::DEFAULT_CHAT_CUSTODY_COPIES,
            custody_collect_every: Duration::from_secs(300),
            // Baseline for tests and embedders; the daemon takes the mode from
            // `privacy.pqc_mode` (default `prefer`) when it starts.
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
        custody_enabled: cfg.chat.custody_enabled,
        custody_copies: cfg.chat.custody_copies.clamp(1, 8),
        pqc_mode: cfg.privacy.pqc_mode(),
        anchor_dir: crate::paths::anchor_dir(data_dir),
        ..ChatSettings::default()
    };
    // Only a value somebody set is worth a warning; the default is not a request.
    if cfg.privacy.pqc_mode.is_some_and(|m| m != PqcMode::Off) && !PqcMode::available() {
        // Said once, plainly: the setting is on but this build cannot do it.
        warn!(
            "privacy.pqc_mode is {} but this build has no advanced encryption; \
             private conversations stay standard",
            cfg.privacy.pqc_mode()
        );
    }
    // The default is `require` (no classical fallback). A value set explicitly
    // to `off` or `prefer` lowers that and allows the classical session; warn
    // while one is in force so the weaker guarantee is visible.
    if cfg
        .privacy
        .pqc_mode
        .is_some_and(|m| m.allows_classical_fallback())
        && PqcMode::available()
    {
        warn!(
            "privacy.pqc_mode is {}: a classical fallback is allowed for private \
             conversations instead of the required post-quantum exchange",
            cfg.privacy.pqc_mode()
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
    /// Node-wide count of chat sends in flight, shared with group chat and the
    /// push send loop so the latter can pace itself while chat is sending.
    activity: ChatActivity,
    /// The holder store, when `custody_enabled` is on; `None` keeps the node
    /// holding nothing and answering no custody verb (exactly as before).
    custody: Option<Arc<super::mailbox::holder::MemoryCustody>>,
    /// Wakes the collection task so it asks holders at once (on a fresh inbound
    /// connection, say). The task also runs on its own timer. Unused when
    /// custody is off.
    custody_collect: Arc<Notify>,
    groups: OnceLock<Arc<super::group::service::GroupService>>,
    #[cfg(feature = "pqc")]
    call_sink: Mutex<Option<tokio::sync::mpsc::Sender<super::call::CallInbound>>>,
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
        // With custody on, build the holder store and let every contact this
        // node trusts use it. Trust is re-seeded for a caller on each request
        // too, so a contact added later is served without a restart.
        let custody = if settings.custody_enabled {
            let store =
                super::mailbox::holder::MemoryCustody::new(super::mailbox::holder::CustodyLimits {
                    enabled: true,
                    ..super::mailbox::holder::CustodyLimits::default()
                });
            for c in contacts.list() {
                if let Some(id) = c.endpoint_bytes() {
                    store.trust(id);
                }
            }
            Some(Arc::new(store))
        } else {
            None
        };
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
            activity: ChatActivity::new(),
            custody,
            custody_collect: Arc::new(Notify::new()),
            groups: OnceLock::new(),
            #[cfg(feature = "pqc")]
            call_sink: Mutex::new(None),
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
        // With custody on, one task asks our trusted holders for anything kept
        // for us: on a timer, and at once whenever it is woken (a contact just
        // connected). It runs even with an empty outbox, so an idle recipient
        // still collects. Each item is applied as a direct delivery, so a copy
        // we already have is dropped.
        if svc.custody.is_some() {
            let me = svc.clone();
            let wake = svc.custody_collect.clone();
            let mut stop = svc.shutdown.subscribe();
            tokio::spawn(async move {
                // A short first pass so a recipient that just came online does
                // not wait a whole period for messages left while it was away.
                tokio::time::sleep(Duration::from_secs(2)).await;
                loop {
                    let worker = me.clone();
                    let _ =
                        tokio::task::spawn_blocking(move || worker.collect_from_holders()).await;
                    tokio::select! {
                        _ = tokio::time::sleep(me.settings.custody_collect_every) => {}
                        _ = wake.notified() => {}
                        _ = stop.changed() => return,
                    }
                }
            });
        }
        info!("chat is on");
        Some(svc)
    }

    /// Register or replace the inbound call signalling sink.
    #[cfg(feature = "pqc")]
    pub fn set_call_sink(&self, tx: tokio::sync::mpsc::Sender<super::call::CallInbound>) {
        if let Ok(mut sink) = self.call_sink.lock() {
            *sink = Some(tx);
        }
    }

    #[cfg(feature = "pqc")]
    pub(crate) fn call_shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
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

    #[cfg(feature = "pqc")]
    pub(crate) fn sas_inputs(&self, peer: &[u8; 32]) -> Option<super::call::controller::SasInputs> {
        self.core.sas_inputs(peer)
    }

    #[cfg(feature = "pqc")]
    pub(crate) fn media_gate(&self, peer: &[u8; 32]) -> super::call::controller::MediaGate {
        self.core.media_gate(peer)
    }

    pub fn settings(&self) -> &ChatSettings {
        &self.settings
    }

    /// The node-wide count of chat sends in flight. Shared with group chat and
    /// read by the push send loop so it can pace itself while chat is sending.
    pub fn chat_activity(&self) -> &ChatActivity {
        &self.activity
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

    /// Wake the custody collection task so it asks our holders right away.
    /// A no-op when custody is off.
    pub fn kick_collect(&self) {
        if self.custody.is_some() {
            self.custody_collect.notify_one();
        }
    }

    /// A snapshot of what this node is holding for others, when custody is on.
    pub fn custody_stats(&self) -> Option<super::mailbox::holder::CustodyStats> {
        self.custody.as_ref().map(|c| c.stats())
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
                    // A direct send that did not go through: leave a copy with
                    // trusted holders (text only, not a read receipt), so the
                    // contact can collect it while we cannot reach it. The
                    // sealed bytes are the same the direct send used, so a
                    // duplicate is dropped on arrival.
                    if self.custody.is_some() && entry.kind != OutKind::Read {
                        if let Ok((wire, _)) = self.core.prepare_wire(&entry.id) {
                            let me = self.clone();
                            let peer = peer;
                            tokio::task::spawn_blocking(move || {
                                me.deposit_with_holders(&peer, &wire)
                            })
                            .await
                            .ok();
                        }
                    }
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
        // Raised while this send holds the uplink, so the push loop paces
        // itself; lowered as soon as the acknowledgement is in. Dropped on
        // every path out of this scope, including the early returns below.
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

    // ── Custody ──────────────────────────────────────────────────────────────

    /// Whether `peer` is a contact this node accepts messages from (and so may
    /// also use custody).
    fn contact_may_write(&self, peer: &[u8; 32]) -> bool {
        matches!(self.contacts.by_endpoint(peer), Some(c) if c.allow_receive)
    }

    /// Answer one custody request on an open stream. The caller `who` is the
    /// authenticated peer; it is trusted afresh here so a contact added after
    /// start is served. A refusal is a frame, not a closed connection.
    async fn serve_custody(
        &self,
        who: &[u8; 32],
        tx: &mut iroh::endpoint::SendStream,
        rx: &mut iroh::endpoint::RecvStream,
    ) {
        use super::mailbox::holder::CustodyStore;
        use super::mailbox::wire::{self, Request, Response};
        let Some(store) = self.custody.clone() else {
            return;
        };
        store.trust(*who);
        let req =
            match tokio::time::timeout(self.settings.read_timeout, wire::read_request(rx)).await {
                Ok(Ok(r)) => r,
                _ => return,
            };
        let now = now_ms();
        let who = *who;
        let resp = tokio::task::spawn_blocking(move || match req {
            Request::Deposit { tag, item, blob } => {
                match store.deposit(&who, tag, item, &blob, now) {
                    Ok(o) => Response::Deposited(o),
                    Err(e) => Response::Refused(e),
                }
            }
            Request::List { tag, now_ms } => match store.list(&who, tag, now_ms) {
                Ok(v) => Response::Listing(v),
                Err(e) => Response::Refused(e),
            },
            Request::Fetch { tag, item, now_ms } => match store.fetch(&who, tag, item, now_ms) {
                Ok(o) => Response::Item(o),
                Err(e) => Response::Refused(e),
            },
            Request::Delete { tag, item } => match store.delete(&who, tag, item) {
                Ok(b) => Response::Deleted(b),
                Err(e) => Response::Refused(e),
            },
        })
        .await;
        let resp = match resp {
            Ok(r) => r,
            Err(_) => return,
        };
        let _ = wire::write_response(tx, &resp).await;
        let _ = tx.finish();
    }

    /// The trusted contacts, other than `peer`, that could hold a copy for it.
    fn holders_for(&self, peer: &[u8; 32]) -> Vec<[u8; 32]> {
        self.contacts
            .list()
            .into_iter()
            .filter_map(|c| c.endpoint_bytes())
            .filter(|id| id != peer)
            .collect()
    }

    /// Leave a copy of the sealed envelope for `peer` with trusted holders,
    /// after a direct send could not go through. Does nothing when custody is
    /// off or there is no holder to ask. The envelope is the same bytes the
    /// direct send would have used, so the recipient drops a duplicate.
    fn deposit_with_holders(&self, peer: &[u8; 32], wire: &[u8]) {
        if self.custody.is_none() {
            return;
        }
        let Some(item) = super::mailbox::ids::item_id_of(wire) else {
            return;
        };
        let holders = self.holders_for(peer);
        if holders.is_empty() {
            return;
        }
        let client = super::mailbox::client::MailboxClient::new(
            super::mailbox::transport::ChatMailboxTransport::new(self.node.clone()),
            self.settings.custody_copies,
        );
        let me = self.core.own_id();
        let rep = client.deposit(&holders, &me, peer, item, wire, now_ms());
        if !rep.held_by.is_empty() {
            debug!(
                peer = %fingerprint(peer),
                "left a copy with {} holder(s)", rep.held_by.len()
            );
        }
    }

    /// Collect from trusted holders whatever waits for us, applying each item
    /// once as a direct delivery. Does nothing when custody is off.
    fn collect_from_holders(&self) {
        if self.custody.is_none() {
            return;
        }
        let holders: Vec<[u8; 32]> = self
            .contacts
            .list()
            .into_iter()
            .filter_map(|c| c.endpoint_bytes())
            .collect();
        if holders.is_empty() {
            return;
        }
        let client = super::mailbox::client::MailboxClient::new(
            super::mailbox::transport::ChatMailboxTransport::new(self.node.clone()),
            self.settings.custody_copies,
        );
        let me = self.core.own_id();
        let core = self.core.clone();
        let rep = client.collect(&holders, &me, now_ms(), |sender, wire| {
            core.accept(sender, wire, now_ms()).status.is_delivered()
        });
        if rep.taken > 0 {
            debug!("collected {} message(s) from holders", rep.taken);
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
                // The contact is online: let our own queue for it go out now,
                // and ask our holders in case this contact (or any) kept
                // something for us while we were away.
                self.kick(&remote);
                self.kick_collect();
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
            // One byte is read first. A custody request (deposit/list/fetch/
            // delete) begins with CUSTODY_STREAM_TAG (0xC0); a chat frame
            // begins with the high byte of its length, always 0x00 for a body
            // within MAX_FRAME_BODY, so the two can never be confused and a
            // build from before custody never sends the tag. The byte is
            // restored in front of the stream for the chat path.
            let first = tokio::time::timeout(self.settings.read_timeout, rx.read_u8()).await;
            let first = match first {
                Ok(Ok(b)) => b,
                _ => break,
            };
            if first == super::mailbox::wire::CUSTODY_STREAM_TAG {
                if self.custody.is_some() && self.contact_may_write(&remote) {
                    self.serve_custody(&remote, &mut tx, &mut rx).await;
                } else {
                    // Not offering custody, or not a contact that may use it.
                    conn.close(CLOSE_NOT_ALLOWED.into(), b"");
                    return;
                }
                continue;
            }
            let first_byte = [first];
            let mut rx = AsyncReadExt::chain(&first_byte[..], rx);
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
                #[cfg(feature = "pqc")]
                let sink = self.call_sink.lock().ok().and_then(|s| s.clone());
                #[cfg(feature = "pqc")]
                let contacts = self.contacts.clone();
                match tokio::task::spawn_blocking(move || {
                    #[cfg(feature = "pqc")]
                    if let Some(sink) = sink {
                        let now = now_ms();
                        return core.accept_with_call(&remote, &w, now, &|body| {
                            let allowed =
                                matches!(contacts.by_endpoint(&remote), Some(c) if c.allow_receive);
                            super::call::inbound::dispatch(&sink, remote, allowed, body, now_ms());
                        });
                    }
                    core.accept(&remote, &w, now_ms())
                })
                .await
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
            Pass::Refuse(refusal) => {
                // `require`: nothing goes out in the classical session. The
                // message stays in the history as failed, with the reason.
                debug!(
                    peer = %fingerprint(refusal.peer()),
                    "private conversation refused (no classical fallback): {}",
                    refusal.reason_str()
                );
                if let Some(e) = first {
                    self.core.mark_failed(&e.id, refusal.reason_str(), now_ms());
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
