//! The push service: the receiving side (accepts connections from contacts),
//! the sending side (per-contact sequential queues), and the bookkeeping the
//! IPC layer exposes.
//!
//! Identity: the only identity of a peer is `Link::remote_id()`, proven
//! by the QUIC/TLS handshake. Nothing in a message is believed about who the
//! peer is.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufWriter},
    sync::{broadcast, watch, Notify, Semaphore},
    time::Instant,
};
use tracing::{debug, info};

use super::{
    contact::{fingerprint, ContactCode},
    link::{BoxRx, BoxTx, CloseInfo, Dialer, IrohDialer, IrohLink, Link},
    outbox::{OutJob, Outbox},
    proto::{
        self, Done, Header, ProtoError, RejectReason, Reply, CLOSE_BAD_REQUEST, CLOSE_NOT_ALLOWED,
        CLOSE_OK, PROTOCOL_VERSION,
    },
    retry::RetryPolicy,
    state::{
        error_kind, now_ms, Board, Direction, History, HistoryEntry, PushState, PushTransferInfo,
        RateMeter, MAX_ACTIVE,
    },
    store::{Contact, ContactError, ContactStore, ContactUpdate},
};
use crate::{
    config::PushConfig,
    transfer::manifest::sanitize_file_name,
    transport::iroh_direct::{IrohClientError, IrohNode, PushConnectionHandler},
};

/// Sending reads and the receiver's writes use chunks of this size.
const CHUNK: usize = 256 * 1024;
/// Streams (files) served on one connection before it is closed.
const MAX_STREAMS_PER_CONNECTION: usize = 10_000;
const MAX_QUEUED_PER_SERVICE: usize = MAX_ACTIVE;
/// How often old partial files are looked for (the first look is at start).
const PART_SWEEP_EVERY: Duration = Duration::from_secs(24 * 3600);
/// Close code of a connection the sender gives up on because it is stuck or
/// broken, to be resumed on a new one. Any code except "cancelled" keeps the
/// receiver's partial file.
const CLOSE_RETRY: u32 = 408;
/// Close code of a receive that a newer connection for the same file replaced.
const CLOSE_SUPERSEDED: u32 = 409;

type FreeSpaceFn = Arc<dyn Fn(&Path) -> Option<u64> + Send + Sync>;

/// Runtime settings (derived from `[push]` in `config.toml`).
#[derive(Clone)]
pub struct PushSettings {
    pub inbox_dir: PathBuf,
    pub max_file_size: u64,
    pub min_free_bytes: u64,
    pub max_concurrent_inbound: usize,
    /// Receiving: no byte arrived for this long => the transfer is left
    /// unfinished (its partial file is kept for a resume).
    pub idle_timeout: Duration,
    /// Sending: no byte accepted by the connection for this long => the
    /// connection is closed and the send resumes on a new one.
    pub stall_timeout: Duration,
    /// How long to wait for the other side's reply to the header and for the
    /// final verification (hashing a multi-GB file takes a while).
    pub reply_timeout: Duration,
    /// When a send tries again after the other side could not be reached.
    pub retry: RetryPolicy,
    /// Unfinished `.part` files older than this are removed (at start and once
    /// a day). `Duration::ZERO` keeps them forever.
    pub part_retention: Duration,
    /// Replaces the real disk query (tests).
    pub free_space: Option<FreeSpaceFn>,
}

impl PushSettings {
    pub fn from_config(cfg: &PushConfig, data_dir: &Path) -> Self {
        Self {
            inbox_dir: cfg.resolved_inbox(data_dir),
            max_file_size: cfg.max_file_size,
            min_free_bytes: cfg.min_free_bytes,
            max_concurrent_inbound: cfg.max_concurrent_inbound.clamp(1, 16),
            idle_timeout: Duration::from_secs(60),
            stall_timeout: Duration::from_secs(cfg.stall_timeout_secs.max(1)),
            reply_timeout: Duration::from_secs(600),
            retry: RetryPolicy::from_config(cfg),
            part_retention: Duration::from_secs(cfg.part_retention_days.saturating_mul(86_400)),
            free_space: None,
        }
    }
}

// ─── Registry (one service per data dir, like the iroh node) ────────────────

static SERVICES: OnceLock<Mutex<HashMap<PathBuf, Arc<PushService>>>> = OnceLock::new();

fn services() -> &'static Mutex<HashMap<PathBuf, Arc<PushService>>> {
    SERVICES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The push service of the daemon that owns `data_dir`, if it runs one.
pub fn service_for(data_dir: &Path) -> Option<Arc<PushService>> {
    services().lock().unwrap().get(data_dir).cloned()
}

pub fn unregister_service(data_dir: &Path) {
    if let Some(s) = services().lock().unwrap().remove(data_dir) {
        s.shutdown();
    }
}

/// Start the service for the daemon of `data_dir`, reading `[push]` from its
/// `config.toml`, and route PUSH_ALPN connections to it.
pub fn start_for_daemon(data_dir: &Path, node: Arc<IrohNode>) -> Arc<PushService> {
    let cfg = crate::config::NodeConfig::load(data_dir)
        .map(|c| c.push)
        .unwrap_or_default();
    let svc = PushService::start(data_dir, node, PushSettings::from_config(&cfg, data_dir));
    services()
        .lock()
        .unwrap()
        .insert(data_dir.to_path_buf(), svc.clone());
    svc
}

// ─── Rate limit for unknown dialers ─────────────────────────────────────────

/// Token bucket per remote id with bounded memory.
struct Limiter {
    buckets: HashMap<[u8; 32], (f64, Instant)>,
}

impl Limiter {
    const CAP: usize = 1024;
    const BURST: f64 = 5.0;
    const REFILL_PER_SEC: f64 = 0.1;

    fn new() -> Self {
        Self {
            buckets: HashMap::new(),
        }
    }

    fn allow(&mut self, id: [u8; 32]) -> bool {
        let now = Instant::now();
        if self.buckets.len() >= Self::CAP && !self.buckets.contains_key(&id) {
            // Forget the stalest quarter rather than grow without bound.
            let mut v: Vec<_> = self.buckets.iter().map(|(k, (_, t))| (*t, *k)).collect();
            v.sort();
            for (_, k) in v.into_iter().take(Self::CAP / 4) {
                self.buckets.remove(&k);
            }
        }
        let e = self.buckets.entry(id).or_insert((Self::BURST, now));
        let dt = now.duration_since(e.1).as_secs_f64();
        e.0 = (e.0 + dt * Self::REFILL_PER_SEC).min(Self::BURST);
        e.1 = now;
        if e.0 >= 1.0 {
            e.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

// ─── The service ─────────────────────────────────────────────────────────────

/// Why a waiting send is told to try again before its timer is up.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Wake {
    /// The home relay is connected again, or the network changed.
    All,
    /// This contact opened a connection to us: it is online.
    Contact(String),
    /// The person pressed "Try now" on this transfer.
    Job(String),
}

struct Job {
    id: String,
    path: PathBuf,
    cancel: watch::Receiver<bool>,
    /// What is stored for this job in the send queue.
    rec: OutJob,
}

#[derive(Default)]
struct ContactQueue {
    jobs: VecDeque<Job>,
    running: bool,
}

pub struct PushService {
    settings: PushSettings,
    contacts: Arc<ContactStore>,
    board: Board,
    history: History,
    own_id: [u8; 32],
    dialer: Arc<dyn Dialer>,
    /// Files waiting to be sent; survives a restart.
    outbox: Outbox,
    wake: broadcast::Sender<Wake>,
    inbound_slots: Arc<Semaphore>,
    /// `.part` files being written, each with the handle that asks the writer
    /// to let go (a newer connection for the same file takes over).
    active_parts: Mutex<HashMap<PathBuf, Arc<Notify>>>,
    limiter: Mutex<Limiter>,
    queues: Mutex<HashMap<String, ContactQueue>>,
    shutdown: watch::Sender<bool>,
}

/// Why one attempt to send failed.
enum AttemptError {
    /// Worth retrying (resume picks up where it stopped). `kind` is the stable
    /// [`error_kind`] shown while waiting and if the retries run out.
    Retry(&'static str, String),
    /// Retry once from scratch (the receiver's hash check failed).
    Restart(String),
    Fatal(String),
    Rejected(RejectReason),
    Cancelled,
    /// The service is shutting down; the job stays queued for the next start.
    Shutdown,
}

/// What one attempt learned, kept by the caller whatever the outcome.
#[derive(Default)]
struct AttemptStats {
    /// The offset the receiver said it already had (set once it accepted).
    accepted: Option<u64>,
}

/// Bookkeeping of one job across its attempts.
struct RetryState {
    /// Failed attempts in a row since bytes last moved.
    failures: u32,
    /// The last time the receiver's confirmed offset grew (or the job began).
    last_progress: Instant,
    /// The largest offset the receiver has confirmed so far.
    best_offset: u64,
    /// When the last attempt began.
    last_start: Option<Instant>,
}

/// Size and modification time of a file, as stored with the queued job.
fn stamp(m: &std::fs::Metadata) -> (u64, u64) {
    let mtime = m
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    (m.len(), mtime)
}

impl PushService {
    /// Create the service and install it as the PUSH_ALPN handler of `node`.
    /// Sends that were queued before the last stop are picked up again.
    pub fn start(data_dir: &Path, node: Arc<IrohNode>, settings: PushSettings) -> Arc<Self> {
        let svc = Self::start_with_dialer(
            data_dir,
            node.endpoint_id(),
            Arc::new(IrohDialer(node.clone())),
            settings,
        );
        node.set_push_handler(svc.clone());
        Self::watch_network(&svc, &node);
        svc
    }

    /// As [`start`](Self::start) over any [`Dialer`]; the caller routes
    /// incoming connections to [`serve_link`](Self::serve_link). This is the
    /// seam fault-injection tests use.
    pub fn start_with_dialer(
        data_dir: &Path,
        own_id: [u8; 32],
        dialer: Arc<dyn Dialer>,
        settings: PushSettings,
    ) -> Arc<Self> {
        let contacts = Arc::new(ContactStore::open(data_dir));
        let (shutdown, _) = watch::channel(false);
        let (wake, _) = broadcast::channel(64);
        let svc = Arc::new(Self {
            inbound_slots: Arc::new(Semaphore::new(settings.max_concurrent_inbound)),
            settings,
            contacts,
            board: Board::new(),
            history: History::open(data_dir),
            own_id,
            dialer,
            outbox: Outbox::open(data_dir),
            wake,
            active_parts: Mutex::new(HashMap::new()),
            limiter: Mutex::new(Limiter::new()),
            queues: Mutex::new(HashMap::new()),
            shutdown,
        });
        // Old partial files of transfers the sender never resumed: once now, then daily.
        {
            let me = svc.clone();
            let mut stop = svc.shutdown.subscribe();
            tokio::spawn(async move {
                loop {
                    let n = me.sweep_partials();
                    if n > 0 {
                        info!("removed {n} unfinished partial file(s) older than the retention");
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(PART_SWEEP_EVERY) => {}
                        _ = stop.changed() => return,
                    }
                }
            });
        }
        let restored = svc.restore_jobs();
        info!(
            contacts = svc.contacts.list().len(),
            resumed_sends = restored,
            "trusted-contact push is on"
        );
        svc
    }

    /// Put the sends stored by an earlier run back in their queues.
    fn restore_jobs(self: &Arc<Self>) -> usize {
        let mut n = 0;
        for rec in self.outbox.jobs() {
            let Some(contact) = self.contacts.find(&rec.contact_id) else {
                self.outbox.remove(&rec.id);
                continue;
            };
            if n >= MAX_QUEUED_PER_SERVICE {
                self.outbox.remove(&rec.id);
                continue;
            }
            let (id, cancel) = self.board.create_with_id(
                rec.id.clone(),
                Direction::Out,
                &contact.id,
                &contact.label,
                &rec.name,
                rec.size,
                PushState::Queued,
            );
            let (shown, offset) = (rec.path.clone(), rec.offset);
            self.board.update(&id, |i| {
                i.source_path = Some(shown);
                i.bytes = offset;
            });
            // The time the daemon was off does not count against the retry window.
            let rec = OutJob { attempt: 0, ..rec };
            self.enqueue_job(
                &contact.id,
                Job {
                    id,
                    path: PathBuf::from(&rec.path),
                    cancel,
                    rec,
                },
            );
            n += 1;
        }
        n
    }

    /// Follow the endpoint: when the home relay connects, or the network the
    /// endpoint sees changes, every waiting send tries again at once.
    fn watch_network(svc: &Arc<Self>, node: &Arc<IrohNode>) {
        use iroh::Watcher;
        let ep = node.endpoint().clone();
        let weak = Arc::downgrade(svc);
        let mut stop = svc.shutdown.subscribe();
        tokio::spawn(async move {
            let mut relay = ep.home_relay_status();
            let mut report = ep.net_report();
            let mut was_up = relay.get().iter().any(|r| r.is_connected());
            let mut last_net = None;
            loop {
                tokio::select! {
                    _ = stop.changed() => return,
                    r = relay.updated() => {
                        let Ok(v) = r else { return };
                        let up = v.iter().any(|r| r.is_connected());
                        if up && !was_up {
                            let Some(s) = weak.upgrade() else { return };
                            s.notify_relay_connected();
                        }
                        was_up = up;
                    }
                    r = report.updated() => {
                        let Ok(v) = r else { return };
                        let now = v.map(|r| (r.udp_v4, r.udp_v6, r.global_v4, r.global_v6, r.preferred_relay));
                        if now.is_some() && last_net.is_some() && now != last_net {
                            let Some(s) = weak.upgrade() else { return };
                            s.notify_network_change();
                        }
                        if now.is_some() {
                            last_net = now;
                        }
                    }
                }
            }
        });
    }

    /// The home relay is connected again: waiting sends try again now.
    pub fn notify_relay_connected(&self) {
        let _ = self.wake.send(Wake::All);
    }

    /// The network changed (new address, interface or path): waiting sends
    /// try again now.
    pub fn notify_network_change(&self) {
        let _ = self.wake.send(Wake::All);
    }

    /// Try a waiting send now instead of at its timer. `false` if `id` is not
    /// a send that is waiting.
    pub fn retry_now(&self, id: &str) -> bool {
        match self.board.get(id) {
            Some(i) if i.direction == Direction::Out && i.state == PushState::Waiting => {
                let _ = self.wake.send(Wake::Job(id.to_owned()));
                true
            }
            _ => false,
        }
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    pub fn contacts(&self) -> &Arc<ContactStore> {
        &self.contacts
    }

    pub fn board(&self) -> &Board {
        &self.board
    }

    pub fn history(&self) -> &History {
        &self.history
    }

    /// Largest file accepted from a contact that has no limit of its own.
    pub fn default_max_file_size(&self) -> u64 {
        self.settings.max_file_size
    }

    pub fn inbox_dir(&self) -> &Path {
        &self.settings.inbox_dir
    }

    pub fn own_endpoint_id(&self) -> [u8; 32] {
        self.own_id
    }

    pub fn my_code(&self) -> ContactCode {
        ContactCode::new(self.own_id)
    }

    fn free_space(&self, p: &Path) -> Option<u64> {
        match &self.settings.free_space {
            Some(f) => f(p),
            None => super::disk::free_space(p),
        }
    }

    // ── Contact management (cancels what the change forbids) ────────────────

    pub fn add_contact(
        &self,
        code: &ContactCode,
        label: Option<&str>,
    ) -> Result<Contact, ContactError> {
        self.contacts.add(code, label, Some(&self.own_id))
    }

    /// [`add_contact`](Self::add_contact) with sending and receiving both set to `allowed`.
    pub fn add_contact_with(
        &self,
        code: &ContactCode,
        label: Option<&str>,
        allowed: bool,
    ) -> Result<Contact, ContactError> {
        self.contacts
            .add_with(code, label, Some(&self.own_id), allowed)
    }

    pub fn update_contact(
        &self,
        selector: &str,
        up: &ContactUpdate,
    ) -> Result<Contact, ContactError> {
        let before = self.contacts.find(selector);
        let after = self.contacts.update(selector, up)?;
        if up.allow_receive == Some(false) {
            self.board.cancel_contact(&after.id, Some(Direction::In));
        }
        if up.allow_send == Some(false) {
            self.board.cancel_contact(&after.id, Some(Direction::Out));
        }
        // A rename moves the inbox folder name for future files only; files
        // already received stay where they are.
        let _ = before;
        Ok(after)
    }

    pub fn remove_contact(&self, selector: &str) -> Result<Contact, ContactError> {
        let removed = self.contacts.remove(selector)?;
        let n = self.board.cancel_contact(&removed.id, None);
        if n > 0 {
            info!("contact removed: cancelled {n} transfer(s)");
        }
        self.clean_partials(&removed);
        Ok(removed)
    }

    /// Remove unfinished `.part` files that have not been written to for the
    /// retention time (`push.part_retention_days`). Only files of exactly our
    /// own name pattern, directly inside a contact folder of the inbox, and not
    /// in use. Returns how many were removed.
    pub fn sweep_partials(&self) -> usize {
        let active: HashSet<PathBuf> = self.active_parts.lock().unwrap().keys().cloned().collect();
        sweep_partials_in(
            &self.settings.inbox_dir,
            self.settings.part_retention,
            &active,
            std::time::SystemTime::now(),
        )
    }

    /// Delete the unfinished `.part` files of a contact that is no longer
    /// trusted (those not in use; running transfers delete their own).
    fn clean_partials(&self, c: &Contact) {
        let dir = self.contact_dir(&c.label);
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return;
        };
        let active: HashSet<PathBuf> = self.active_parts.lock().unwrap().keys().cloned().collect();
        for e in rd.flatten() {
            let p = e.path();
            let n = e.file_name().to_string_lossy().into_owned();
            if crate::paths::is_push_part_name(&n) && !active.contains(&p) {
                let _ = std::fs::remove_file(&p);
            }
        }
        let _ = std::fs::remove_dir(&dir); // only if empty
    }

    pub fn contact_dir(&self, label: &str) -> PathBuf {
        let leaf = sanitize_file_name(label).unwrap_or_else(|| "contact".to_owned());
        self.settings.inbox_dir.join(leaf)
    }

    // ── Sending ──────────────────────────────────────────────────────────────

    /// Queue `path` for `selector`'s contact. Returns the transfer id. The
    /// send is stored, so it continues after a restart of the daemon.
    pub fn queue_send(self: &Arc<Self>, selector: &str, path: &Path) -> Result<String, String> {
        let contact = self
            .contacts
            .find(selector)
            .ok_or_else(|| format!("unknown_contact: no contact \"{selector}\""))?;
        if !contact.allow_send {
            return Err(format!(
                "send_disabled: sending to \"{}\" is switched off",
                contact.label
            ));
        }
        let meta =
            std::fs::metadata(path).map_err(|e| format!("bad_file: cannot read the file: {e}"))?;
        if !meta.is_file() {
            return Err("bad_file: only files can be sent (not folders)".into());
        }
        if self.board.active_count() >= MAX_QUEUED_PER_SERVICE {
            return Err(
                "queue_full: too many transfers are queued; wait for some to finish".into(),
            );
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let (id, cancel) = self.board.create(
            Direction::Out,
            &contact.id,
            &contact.label,
            &name,
            meta.len(),
            PushState::Queued,
        );
        let shown_path = path.to_string_lossy().into_owned();
        self.board
            .update(&id, |i| i.source_path = Some(shown_path.clone()));
        let (size, mtime_ms) = stamp(&meta);
        let rec = OutJob {
            id: id.clone(),
            contact_id: contact.id.clone(),
            path: shown_path,
            name,
            size,
            mtime_ms,
            hash: None,
            offset: 0,
            attempt: 0,
            created_at_ms: now_ms(),
        };
        self.outbox.put(&rec, true);
        self.enqueue_job(
            &contact.id,
            Job {
                id: id.clone(),
                path: path.to_path_buf(),
                cancel,
                rec,
            },
        );
        Ok(id)
    }

    fn enqueue_job(self: &Arc<Self>, contact_id: &str, job: Job) {
        let start_worker = {
            let mut q = self.queues.lock().unwrap();
            let cq = q.entry(contact_id.to_owned()).or_default();
            cq.jobs.push_back(job);
            !std::mem::replace(&mut cq.running, true)
        };
        if start_worker {
            let me = self.clone();
            let cid = contact_id.to_owned();
            tokio::spawn(async move { me.worker(cid).await });
        }
    }

    async fn worker(self: Arc<Self>, contact_id: String) {
        let mut conn: Option<Arc<dyn Link>> = None;
        let stop = self.shutdown.subscribe();
        loop {
            if *stop.borrow() {
                break;
            }
            let job = {
                let mut q = self.queues.lock().unwrap();
                let Some(cq) = q.get_mut(&contact_id) else {
                    return;
                };
                match cq.jobs.pop_front() {
                    Some(j) => j,
                    None => {
                        cq.running = false;
                        break;
                    }
                }
            };
            self.run_job(&contact_id, &mut conn, job).await;
        }
        if let Some(c) = conn {
            c.close(CLOSE_OK, b"done");
        }
    }

    fn finish(
        &self,
        id: &str,
        state: PushState,
        error: Option<String>,
        reason: Option<RejectReason>,
    ) {
        self.finish_kind(id, state, error, reason, None)
    }

    fn finish_kind(
        &self,
        id: &str,
        state: PushState,
        error: Option<String>,
        reason: Option<RejectReason>,
        kind: Option<&str>,
    ) {
        // Whatever the ending, the send is no longer wanted after a restart.
        self.outbox.remove(id);
        self.board.update(id, |i| {
            i.state = state;
            i.error = error;
            i.reject_reason = reason.map(|r| r.as_str().to_owned());
            i.error_kind = kind.map(str::to_owned);
            i.rate_bps = 0;
            i.next_attempt_at_ms = None;
            i.attempt = None;
            if state == PushState::Done {
                i.bytes = i.size;
            }
        });
        if let Some(i) = self.board.get(id) {
            self.history.append(&HistoryEntry {
                id: i.id,
                direction: i.direction,
                contact_id: i.contact_id,
                contact_label: i.contact_label,
                name: i.name,
                size: i.size,
                state: i.state,
                error: i.error,
                reject_reason: i.reject_reason,
                error_kind: i.error_kind,
                source_path: i.source_path,
                saved_as: i.saved_as,
                finished_at_ms: now_ms(),
            });
        }
    }

    async fn run_job(&self, contact_id: &str, conn: &mut Option<Arc<dyn Link>>, mut job: Job) {
        let id = job.id.clone();
        let mut stop = self.shutdown.subscribe();
        if *job.cancel.borrow() {
            return self.finish(&id, PushState::Cancelled, None, None);
        }
        let Some(contact) = self.contacts.find(contact_id) else {
            return self.finish_kind(
                &id,
                PushState::Cancelled,
                Some("the contact was removed".into()),
                None,
                Some(error_kind::CONTACT_CHANGED),
            );
        };
        if !contact.allow_send {
            return self.finish_kind(
                &id,
                PushState::Failed,
                Some("sending to this contact is switched off".into()),
                None,
                Some(error_kind::CONTACT_CHANGED),
            );
        }
        let Some(target) = contact.endpoint_bytes() else {
            return self.finish(
                &id,
                PushState::Failed,
                Some("the contact has no valid key".into()),
                None,
            );
        };

        // The file must still be the one that was queued.
        if let Err((kind, m)) = self.check_source(&job) {
            return self.finish_kind(&id, PushState::Failed, Some(m), None, Some(kind));
        }

        // Hash first: the header carries it, and it is the resume key. A hash
        // stored with the queued job (a restart) is not computed again.
        let size = job.rec.size;
        let hash = match job.rec.hash.clone() {
            Some(h) => h,
            None => {
                self.board.update(&id, |i| i.state = PushState::Preparing);
                match hash_file(&job.path, job.cancel.clone()).await {
                    Ok(Some((h, total))) if total == size => {
                        job.rec.hash = Some(h.clone());
                        self.outbox.put(&job.rec, false);
                        h
                    }
                    Ok(Some(_)) => {
                        return self.finish_kind(
                            &id,
                            PushState::Failed,
                            Some("the file changed after it was queued".into()),
                            None,
                            Some(error_kind::SOURCE_CHANGED),
                        )
                    }
                    Ok(None) => return self.finish(&id, PushState::Cancelled, None, None),
                    Err(e) => {
                        return self.finish_kind(
                            &id,
                            PushState::Failed,
                            Some(format!("cannot read the file: {e}")),
                            None,
                            Some(error_kind::FILE_UNREADABLE),
                        )
                    }
                }
            }
        };
        self.board.update(&id, |i| i.size = size);
        let name = job.rec.name.clone();

        let mut st = RetryState {
            failures: 0,
            last_progress: Instant::now(),
            best_offset: 0,
            last_start: None,
        };
        let mut restarted = false;
        loop {
            if *job.cancel.borrow() {
                return self.finish(&id, PushState::Cancelled, None, None);
            }
            if *stop.borrow() {
                return;
            }
            if let Err((kind, m)) = self.check_source(&job) {
                return self.finish_kind(&id, PushState::Failed, Some(m), None, Some(kind));
            }
            self.board.update(&id, |i| {
                i.state = PushState::Connecting;
                i.next_attempt_at_ms = None;
            });
            st.last_start = Some(Instant::now());
            let c = match self.ensure_conn(conn, &target).await {
                Ok(c) => c,
                Err(e) => {
                    let kind = match e {
                        IrohClientError::Unreachable(_) => error_kind::UNREACHABLE,
                        _ => error_kind::CONNECTION_LOST,
                    };
                    if self
                        .wait_retry(&mut job, &mut st, kind, describe_dial_error(&e), &mut stop)
                        .await
                    {
                        continue;
                    }
                    return;
                }
            };
            let mut stats = AttemptStats::default();
            let res = self
                .attempt_send(
                    &*c,
                    &id,
                    &job.path,
                    &name,
                    size,
                    &hash,
                    &mut job.cancel,
                    &mut stop,
                    &mut stats,
                )
                .await;
            // The receiver confirmed more than it had before: the transfer
            // is moving, so the waits start from the short end again.
            if let Some(a) = stats.accepted {
                if a > st.best_offset {
                    st.best_offset = a;
                    st.failures = 0;
                    st.last_progress = Instant::now();
                }
            }
            match res {
                Ok(saved) => {
                    self.board.update(&id, |i| i.saved_as = saved);
                    return self.finish(&id, PushState::Done, None, None);
                }
                Err(AttemptError::Cancelled) => {
                    // Closing with CLOSE_CANCELLED tells the receiver this was on
                    // purpose (it then deletes its partial file); a connection that
                    // merely dies keeps the partial for a later resume.
                    *conn = None;
                    c.close(proto::CLOSE_CANCELLED, b"cancelled");
                    return self.finish(&id, PushState::Cancelled, None, None);
                }
                Err(AttemptError::Shutdown) => {
                    *conn = None;
                    c.close(CLOSE_OK, b"shutdown");
                    return;
                }
                Err(AttemptError::Rejected(RejectReason::Busy)) => {
                    // The receiver still holds the previous attempt; it lets go soon.
                    if !self
                        .wait_retry(
                            &mut job,
                            &mut st,
                            error_kind::CONNECTION_LOST,
                            reject_text(RejectReason::Busy),
                            &mut stop,
                        )
                        .await
                    {
                        return;
                    }
                }
                Err(AttemptError::Rejected(r)) => {
                    return self.finish(&id, PushState::Rejected, Some(reject_text(r)), Some(r));
                }
                Err(AttemptError::Fatal(m)) => {
                    let kind = fatal_kind(&m);
                    return self.finish_kind(&id, PushState::Failed, Some(m), None, kind);
                }
                Err(AttemptError::Restart(m)) => {
                    if restarted {
                        return self.finish_kind(
                            &id,
                            PushState::Failed,
                            Some(m),
                            None,
                            Some(error_kind::DAMAGED),
                        );
                    }
                    restarted = true;
                }
                Err(AttemptError::Retry(kind, m)) => {
                    // Let go of the broken connection on purpose, so the receiver
                    // frees the partial file for the next attempt at once.
                    *conn = None;
                    c.close(CLOSE_RETRY, b"retry");
                    if !self.wait_retry(&mut job, &mut st, kind, m, &mut stop).await {
                        return;
                    }
                }
            }
        }
    }

    /// The source file must still be what was queued.
    fn check_source(&self, job: &Job) -> Result<(), (&'static str, String)> {
        match std::fs::metadata(&job.path) {
            Ok(m) if m.is_file() && stamp(&m) == (job.rec.size, job.rec.mtime_ms) => Ok(()),
            Ok(_) => Err((
                error_kind::SOURCE_CHANGED,
                "the file changed after it was queued; send it again".into(),
            )),
            Err(e) => Err((
                error_kind::FILE_UNREADABLE,
                format!("cannot read the file: {e}"),
            )),
        }
    }

    /// The other side could not be reached (or the connection broke): show
    /// `Waiting`, store the progress, and sleep until the timer runs out, a
    /// wake-up arrives, or the send is cancelled. `true` = try again; `false`
    /// = the job has been finished (or the service is stopping), return.
    async fn wait_retry(
        &self,
        job: &mut Job,
        st: &mut RetryState,
        kind: &'static str,
        msg: String,
        stop: &mut watch::Receiver<bool>,
    ) -> bool {
        let id = job.id.clone();
        st.failures += 1;
        let policy = &self.settings.retry;
        if policy.exhausted(st.last_progress.elapsed()) {
            let text = match policy.window {
                Some(w) if !w.is_zero() => format!(
                    "gave up after retrying for {} min: {msg}",
                    (w.as_secs() / 60).max(1)
                ),
                _ => msg,
            };
            self.finish_kind(&id, PushState::Failed, Some(text), None, Some(kind));
            return false;
        }
        let delay = policy.delay(st.failures, rand::random::<f64>());
        let at = now_ms().saturating_add(delay.as_millis() as u64);
        let failures = st.failures;
        let mut offset = 0;
        self.board.update(&id, |i| {
            offset = i.bytes;
            i.state = PushState::Waiting;
            i.error = Some(msg);
            i.error_kind = Some(kind.to_owned());
            i.next_attempt_at_ms = Some(at);
            i.attempt = Some(failures);
            i.rate_bps = 0;
        });
        job.rec.offset = offset;
        job.rec.attempt = failures;
        self.outbox.put(&job.rec, false);

        let mut wake = self.wake.subscribe();
        let mut cancel = job.cancel.clone();
        let timer = tokio::time::sleep(delay);
        tokio::pin!(timer);
        let mut pressed = false;
        loop {
            tokio::select! {
                _ = &mut timer => break,
                _ = wait_cancel(&mut cancel) => {
                    self.finish(&id, PushState::Cancelled, None, None);
                    return false;
                }
                _ = stop.changed() => return false,
                ev = wake.recv() => match ev {
                    Ok(Wake::All) => break,
                    Ok(Wake::Contact(c)) if c == job.rec.contact_id => break,
                    Ok(Wake::Job(j)) if j == id => {
                        pressed = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => break,
                    Err(broadcast::error::RecvError::Closed) => {}
                }
            }
        }
        // A burst of wake-ups must not become a storm of dials ("Try now" is
        // the person's own request and is not held back).
        if !pressed {
            if let Some(t) = st.last_start {
                let gap = self.settings.retry.min_gap;
                if t.elapsed() < gap {
                    let rest = gap - t.elapsed();
                    tokio::select! {
                        _ = tokio::time::sleep(rest) => {}
                        _ = wait_cancel(&mut cancel) => {
                            self.finish(&id, PushState::Cancelled, None, None);
                            return false;
                        }
                        _ = stop.changed() => return false,
                    }
                }
            }
        }
        true
    }

    async fn ensure_conn(
        &self,
        slot: &mut Option<Arc<dyn Link>>,
        target: &[u8; 32],
    ) -> Result<Arc<dyn Link>, IrohClientError> {
        if let Some(c) = slot.as_ref() {
            if c.close_info().is_none() {
                return Ok(c.clone());
            }
        }
        let c = match tokio::time::timeout(Duration::from_secs(120), self.dialer.dial(target)).await
        {
            Ok(r) => r?,
            Err(_) => return Err(IrohClientError::Unreachable("the dial timed out".into())),
        };
        *slot = Some(c.clone());
        Ok(c)
    }

    /// If the connection was closed by the receiver as "not allowed".
    fn closed_as_not_allowed(conn: &dyn Link) -> bool {
        conn.close_info() == Some(CloseInfo::App(u64::from(CLOSE_NOT_ALLOWED)))
    }

    #[allow(clippy::too_many_arguments)]
    async fn attempt_send(
        &self,
        conn: &dyn Link,
        id: &str,
        path: &Path,
        name: &str,
        size: u64,
        hash: &str,
        cancel: &mut watch::Receiver<bool>,
        stop: &mut watch::Receiver<bool>,
        stats: &mut AttemptStats,
    ) -> Result<Option<String>, AttemptError> {
        let stall = self.settings.stall_timeout;
        let broken = |conn: &dyn Link, what: &str, e: String| {
            if Self::closed_as_not_allowed(conn) {
                AttemptError::Rejected(RejectReason::NotAllowed)
            } else {
                AttemptError::Retry(error_kind::CONNECTION_LOST, format!("{what}: {e}"))
            }
        };
        let (mut tx, mut rx): (BoxTx, BoxRx) =
            match tokio::time::timeout(Duration::from_secs(30), conn.open_bi()).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(broken(conn, "open stream", e)),
                Err(_) => {
                    return Err(AttemptError::Retry(
                        error_kind::TIMED_OUT,
                        "open stream timed out".into(),
                    ))
                }
            };
        let header = Header {
            v: PROTOCOL_VERSION,
            name: name.to_owned(),
            size,
            hash: hash.to_owned(),
            note: None,
        };
        if let Err(e) = proto::write_frame(&mut tx, &header).await {
            return Err(broken(conn, "send header", e.to_string()));
        }
        let reply: Reply = tokio::select! {
            _ = wait_cancel(cancel) => return Err(AttemptError::Cancelled),
            _ = stop.changed() => return Err(AttemptError::Shutdown),
            r = tokio::time::timeout(self.settings.reply_timeout, proto::read_frame(&mut rx)) => match r {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => return Err(broken(conn, "no reply", e.to_string())),
                Err(_) => {
                    return Err(AttemptError::Retry(
                        error_kind::TIMED_OUT,
                        "the other side did not reply".into(),
                    ))
                }
            }
        };
        let offset = match reply {
            Reply::Reject { reason } => return Err(AttemptError::Rejected(reason)),
            Reply::Accept { offset } if offset <= size => offset,
            Reply::Accept { .. } => {
                return Err(AttemptError::Fatal(
                    "the other side sent an invalid offset".into(),
                ))
            }
        };
        stats.accepted = Some(offset);

        self.board.update(id, |i| {
            i.state = PushState::Sending;
            i.bytes = offset;
            i.error = None;
            i.error_kind = None;
            i.next_attempt_at_ms = None;
            i.attempt = None;
        });
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|e| AttemptError::Fatal(format!("cannot read the file: {e}")))?;
        if offset > 0 {
            file.seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(|e| AttemptError::Fatal(format!("cannot read the file: {e}")))?;
        }
        let mut buf = vec![0u8; CHUNK];
        // Progress (`bytes` on the board) means the same on both sides: bytes of the file that
        // the QUIC stream has taken from / given to the application, counted from byte 0 of the
        // file (a resumed prefix included). The receiver counts what it has read and written;
        // the sender counts what `write_all` accepted. QUIC flow control keeps the two within
        // the stream's unacknowledged window (about 10 MiB with the transport defaults), so the
        // sender can lead the receiver by at most that, and never lags it. A row that ended
        // (cancelled, failed) keeps the count it had when it stopped; a later retry is a new
        // row that starts at the resumed offset.
        let mut sent = offset;
        let mut meter = RateMeter::new(sent);
        while sent < size {
            let want = (size - sent).min(CHUNK as u64) as usize;
            let n = file
                .read(&mut buf[..want])
                .await
                .map_err(|e| AttemptError::Fatal(format!("cannot read the file: {e}")))?;
            if n == 0 {
                return Err(AttemptError::Fatal(
                    "the file changed while it was being sent".into(),
                ));
            }
            tokio::select! {
                _ = wait_cancel(cancel) => return Err(AttemptError::Cancelled),
                _ = stop.changed() => return Err(AttemptError::Shutdown),
                w = tokio::time::timeout(stall, AsyncWriteExt::write_all(&mut tx, &buf[..n])) => match w {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(broken(conn, "send", e.to_string())),
                    Err(_) => return Err(AttemptError::Retry(
                        error_kind::TIMED_OUT,
                        format!("no data moved for {} s; reconnecting", stall.as_secs()),
                    )),
                }
            }
            sent += n as u64;
            let rate = meter.sample(sent);
            self.board.update(id, |i| {
                i.bytes = sent;
                if let Some(r) = rate {
                    i.rate_bps = r;
                }
            });
        }
        tx.finish();
        self.board.update(id, |i| {
            i.state = PushState::Verifying;
            i.rate_bps = 0;
        });
        let done: Done = tokio::select! {
            _ = wait_cancel(cancel) => return Err(AttemptError::Cancelled),
            _ = stop.changed() => return Err(AttemptError::Shutdown),
            r = tokio::time::timeout(self.settings.reply_timeout, proto::read_frame(&mut rx)) => match r {
                Ok(Ok(d)) => d,
                Ok(Err(e)) => return Err(broken(conn, "no confirmation", e.to_string())),
                Err(_) => return Err(AttemptError::Retry(error_kind::TIMED_OUT, "the other side did not confirm".into())),
            }
        };
        if done.ok {
            Ok(done.saved_as)
        } else {
            let e = done.error.unwrap_or_else(|| "failed".into());
            if e == "hash_mismatch" {
                Err(AttemptError::Restart(
                    "the file arrived damaged (checksum mismatch)".into(),
                ))
            } else {
                Err(AttemptError::Fatal(format!(
                    "the receiver could not save the file: {e}"
                )))
            }
        }
    }

    // ── Receiving ────────────────────────────────────────────────────────────

    /// Returns `false` if the connection was closed.
    async fn receive_one(
        &self,
        conn: &dyn Link,
        contact: Contact,
        mut tx: BoxTx,
        mut rx: BoxRx,
    ) -> bool {
        let header: Header =
            match tokio::time::timeout(Duration::from_secs(30), proto::read_frame(&mut rx)).await {
                Ok(Ok(h)) => h,
                _ => {
                    conn.close(CLOSE_BAD_REQUEST, b"");
                    return false;
                }
            };
        if let Err(e) = header.validate() {
            debug!("push header refused: {e}");
            return self.reject(&mut tx, RejectReason::BadRequest).await;
        }
        let Some(name) = sanitize_file_name(&header.name) else {
            return self.reject(&mut tx, RejectReason::BadName).await;
        };
        let limit = contact.max_file_size.unwrap_or(self.settings.max_file_size);
        if header.size > limit {
            return self.reject(&mut tx, RejectReason::TooLarge).await;
        }
        let Ok(permit) = self.inbound_slots.clone().try_acquire_owned() else {
            return self.reject(&mut tx, RejectReason::Busy).await;
        };

        let (tid, mut cancel) = self.board.create(
            Direction::In,
            &contact.id,
            &contact.label,
            &name,
            header.size,
            PushState::Preparing,
        );
        let outcome = self
            .receive_body(
                conn,
                &contact,
                &name,
                &header,
                &tid,
                &mut tx,
                &mut rx,
                &mut cancel,
            )
            .await;
        drop(permit);
        match outcome {
            RxEnd::Done(saved) => {
                self.board.update(&tid, |i| i.saved_as = Some(saved));
                self.finish(&tid, PushState::Done, None, None);
                true
            }
            RxEnd::Rejected(r) => {
                self.finish(&tid, PushState::Rejected, Some(reject_text(r)), Some(r));
                self.reject(&mut tx, r).await
            }
            RxEnd::Failed(m) => {
                self.finish(&tid, PushState::Failed, Some(m), None);
                true
            }
            RxEnd::FailedKind(kind, m) => {
                self.finish_kind(&tid, PushState::Failed, Some(m), None, Some(kind));
                true
            }
            RxEnd::PeerCancelled => {
                // The sender stopped on purpose; its partial file is already gone.
                self.finish_kind(
                    &tid,
                    PushState::Cancelled,
                    Some("the sender cancelled this transfer".into()),
                    None,
                    Some(error_kind::PEER_CANCELLED),
                );
                false
            }
            RxEnd::Superseded => {
                self.finish_kind(
                    &tid,
                    PushState::Failed,
                    Some("the sender continued on a new connection".into()),
                    None,
                    Some(error_kind::CONNECTION_LOST),
                );
                conn.close(CLOSE_SUPERSEDED, b"superseded");
                false
            }
            RxEnd::Cancelled => {
                self.finish(&tid, PushState::Cancelled, None, None);
                conn.close(proto::CLOSE_CANCELLED, b"cancelled");
                false
            }
        }
    }

    async fn reject(&self, tx: &mut BoxTx, reason: RejectReason) -> bool {
        if proto::write_frame(tx, &Reply::Reject { reason })
            .await
            .is_err()
        {
            return false;
        }
        finish_stream(tx).await;
        true
    }

    #[allow(clippy::too_many_arguments)]
    async fn receive_body(
        &self,
        conn: &dyn Link,
        contact: &Contact,
        name: &str,
        header: &Header,
        tid: &str,
        tx: &mut BoxTx,
        rx: &mut BoxRx,
        cancel: &mut watch::Receiver<bool>,
    ) -> RxEnd {
        let size = header.size;
        let dir = self.contact_dir(&contact.label);
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return RxEnd::Failed(format!("cannot create the inbox folder: {e}"));
        }
        // The part file is keyed by content (hash + size), not by name, so a
        // resume finds it whatever the name and no name can be too long.
        let part = dir.join(crate::paths::push_part_name(&header.hash[..32], size));
        // A newer connection for the same file (the sender gave up on the old
        // one) takes over: the old writer is asked to flush and let go, and
        // the partial file it leaves is what the new one resumes from.
        let me = Arc::new(Notify::new());
        let mut waited = 0u32;
        loop {
            let holder = {
                let mut g = self.active_parts.lock().unwrap();
                match g.get(&part) {
                    Some(h) => Some(h.clone()),
                    None => {
                        g.insert(part.clone(), me.clone());
                        None
                    }
                }
            };
            let Some(holder) = holder else { break };
            holder.notify_one();
            waited += 1;
            if waited > 100 {
                return RxEnd::Rejected(RejectReason::Busy);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let _guard = PartGuard {
            set: &self.active_parts,
            path: part.clone(),
        };

        let mut offset = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
        if offset > size {
            let _ = std::fs::remove_file(&part);
            offset = 0;
        }
        let need = size - offset;
        if let Some(free) = self.free_space(&dir) {
            if free < need.saturating_add(self.settings.min_free_bytes) {
                return RxEnd::Rejected(RejectReason::NoSpace);
            }
        }

        // Hash the part already on disk before accepting more.
        let mut hasher = blake3::Hasher::new();
        if offset > 0 {
            let p = part.clone();
            let c = cancel.clone();
            let prefix = tokio::task::spawn_blocking(move || hash_prefix(&p, offset, &c)).await;
            match prefix {
                Ok(Ok(Some(h))) => hasher = h,
                Ok(Ok(None)) => return RxEnd::Cancelled,
                _ => {
                    // Unreadable partial: start over.
                    let _ = std::fs::remove_file(&part);
                    offset = 0;
                }
            }
        }
        let file = match tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&part)
            .await
        {
            Ok(f) => f,
            Err(e) => return RxEnd::Failed(format!("cannot create the partial file: {e}")),
        };
        if let Err(e) = file.set_len(offset).await {
            return RxEnd::Failed(format!("cannot prepare the partial file: {e}"));
        }
        let mut file = file;
        if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)).await {
            return RxEnd::Failed(format!("cannot prepare the partial file: {e}"));
        }
        let mut w = BufWriter::with_capacity(1 << 20, file);

        self.board.update(tid, |i| {
            i.state = PushState::Sending;
            i.bytes = offset;
        });
        if proto::write_frame(tx, &Reply::Accept { offset })
            .await
            .is_err()
        {
            return RxEnd::Failed("the sender went away".into());
        }

        let mut buf = vec![0u8; CHUNK];
        // `got` is the receiver's side of the progress count described in `attempt_send`.
        let mut got = offset;
        let mut meter = RateMeter::new(got);
        let idle = self.settings.idle_timeout;
        while got < size {
            let want = (size - got).min(CHUNK as u64) as usize;
            let n = tokio::select! {
                _ = wait_cancel(cancel) => {
                    drop(w);
                    let _ = std::fs::remove_file(&part);
                    return RxEnd::Cancelled;
                }
                _ = me.notified() => {
                    // A newer connection for this file wants it: keep what is
                    // written, close this one, let the newcomer resume.
                    let _ = w.flush().await;
                    drop(w);
                    return RxEnd::Superseded;
                }
                r = tokio::time::timeout(idle, AsyncReadExt::read(rx, &mut buf[..want])) => match r {
                    Err(_) => {
                        return rx_broke(conn, w, &part, error_kind::TIMED_OUT,
                            "the sender stopped sending (timed out); it can resume").await;
                    }
                    Ok(Err(e)) => {
                        debug!("push {tid}: read failed: {e}");
                        return rx_broke(conn, w, &part, error_kind::CONNECTION_LOST,
                            "the connection was lost; the sender can resume").await;
                    }
                    Ok(Ok(0)) => {
                        return rx_broke(conn, w, &part, error_kind::CONNECTION_LOST,
                            "the sender ended early; it can resume").await;
                    }
                    Ok(Ok(n)) => n,
                }
            };
            hasher.update(&buf[..n]);
            if let Err(e) = w.write_all(&buf[..n]).await {
                let _ = self.reply_done(tx, false, None, Some("write_failed")).await;
                return RxEnd::FailedKind(
                    error_kind::WRITE_FAILED,
                    format!("cannot write to the inbox: {e}"),
                );
            }
            got += n as u64;
            let rate = meter.sample(got);
            self.board.update(tid, |i| {
                i.bytes = got;
                if let Some(r) = rate {
                    i.rate_bps = r;
                }
            });
        }
        if let Err(e) = w.flush().await {
            let _ = self.reply_done(tx, false, None, Some("write_failed")).await;
            return RxEnd::FailedKind(
                error_kind::WRITE_FAILED,
                format!("cannot write to the inbox: {e}"),
            );
        }
        let file = w.into_inner();
        if let Err(e) = file.sync_all().await {
            debug!("sync_all: {e}");
        }
        drop(file);

        self.board.update(tid, |i| {
            i.state = PushState::Verifying;
            i.rate_bps = 0;
        });
        if hasher.finalize().to_hex().as_str() != header.hash.to_ascii_lowercase() {
            let _ = std::fs::remove_file(&part);
            let _ = self
                .reply_done(tx, false, None, Some("hash_mismatch"))
                .await;
            return RxEnd::FailedKind(
                error_kind::DAMAGED,
                "the file arrived damaged (checksum mismatch)".into(),
            );
        }
        match place_without_overwrite(&part, &dir, name) {
            Ok(final_path) => {
                let saved = final_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| name.to_owned());
                let shown = format!("{}/{}", contact_leaf(&dir), saved);
                let _ = self.reply_done(tx, true, Some(saved), None).await;
                RxEnd::Done(shown)
            }
            Err(e) => {
                let _ = self
                    .reply_done(tx, false, None, Some("rename_failed"))
                    .await;
                RxEnd::Failed(format!("cannot save the file: {e}"))
            }
        }
    }

    async fn reply_done(
        &self,
        tx: &mut BoxTx,
        ok: bool,
        saved_as: Option<String>,
        error: Option<&str>,
    ) -> Result<(), ProtoError> {
        proto::write_frame(
            tx,
            &Done {
                ok,
                saved_as,
                error: error.map(str::to_owned),
            },
        )
        .await?;
        finish_stream(tx).await;
        Ok(())
    }

    /// Everything the IPC `Queue` call shows: unfinished transfers.
    pub fn queue_snapshot(&self) -> Vec<PushTransferInfo> {
        self.board
            .list()
            .into_iter()
            .filter(|i| !i.state.is_finished())
            .collect()
    }
}

#[async_trait::async_trait]
impl PushConnectionHandler for PushService {
    async fn handle(&self, conn: iroh::endpoint::Connection) {
        self.serve_link(Arc::new(IrohLink(conn))).await
    }
}

impl PushService {
    /// Serve one incoming connection until it ends. Used by the iroh handler
    /// and by tests that bring their own [`Link`].
    pub async fn serve_link(&self, conn: Arc<dyn Link>) {
        // Looked up for every stream: a contact removed or switched off
        // mid-connection stops being served at once.
        let remote = conn.remote_id();
        let mut shutdown = self.shutdown.subscribe();
        for _ in 0..MAX_STREAMS_PER_CONNECTION {
            let contact = match self.contacts.by_endpoint(&remote) {
                Some(c) if c.allow_receive => c,
                _ => {
                    self.contacts.note_unknown(&remote);
                    let loud = self.limiter.lock().unwrap().allow(remote);
                    if loud {
                        debug!(peer = %fingerprint(&remote), "push refused: not a contact that may send");
                    }
                    conn.close(CLOSE_NOT_ALLOWED, b"");
                    return;
                }
            };
            // The contact is online: its waiting sends to us can go now.
            let _ = self.wake.send(Wake::Contact(contact.id.clone()));
            let (tx, rx) = tokio::select! {
                _ = shutdown.changed() => break,
                r = tokio::time::timeout(self.settings.idle_timeout, conn.accept_bi()) => match r {
                    Ok(Ok(s)) => s,
                    _ => break,
                }
            };
            if !self.receive_one(&*conn, contact, tx, rx).await {
                return;
            }
        }
        conn.close(CLOSE_OK, b"done");
    }
}

enum RxEnd {
    Done(String),
    Rejected(RejectReason),
    Failed(String),
    /// Failed, with a stable [`error_kind`] for the UIs.
    FailedKind(&'static str, String),
    /// The sender closed the connection with `CLOSE_CANCELLED`: it meant to stop.
    PeerCancelled,
    /// Stopped on this side (the person, or the contact was removed).
    Cancelled,
    /// A newer connection for the same file took over; the partial is kept.
    Superseded,
}

/// The inbound stream broke. If the sender closed the connection on purpose
/// (`CLOSE_CANCELLED`), delete the partial file: nobody will resume it. Any
/// other loss (network, the sender's process died) keeps the partial for a
/// resume; the retention sweep removes it if the sender never comes back.
async fn rx_broke(
    conn: &dyn Link,
    mut w: BufWriter<tokio::fs::File>,
    part: &Path,
    kind: &'static str,
    text: &str,
) -> RxEnd {
    if closed_by_peer_cancel(conn).await {
        drop(w);
        let _ = std::fs::remove_file(part);
        return RxEnd::PeerCancelled;
    }
    let _ = w.flush().await;
    RxEnd::FailedKind(kind, text.to_owned())
}

/// Did the other side close `conn` with the "cancelled" application code?
/// The close frame may arrive a moment after the read error that revealed it.
async fn closed_by_peer_cancel(conn: &dyn Link) -> bool {
    let reason = match conn.close_info() {
        Some(r) => Some(r),
        None => tokio::time::timeout(Duration::from_millis(500), conn.closed())
            .await
            .ok(),
    };
    reason == Some(CloseInfo::App(u64::from(proto::CLOSE_CANCELLED)))
}

/// Stable kind of a sender-side `Fatal` message (they are our own texts).
fn fatal_kind(m: &str) -> Option<&'static str> {
    if m.starts_with("the file changed") {
        Some(error_kind::SOURCE_CHANGED)
    } else if m.starts_with("cannot read the file") {
        Some(error_kind::FILE_UNREADABLE)
    } else if m.starts_with("the receiver could not save") {
        Some(error_kind::WRITE_FAILED)
    } else {
        None
    }
}

/// `.<32 hex of the hash>-<size>.part`: the only files the sweep may remove.
fn is_our_part_name(name: &str) -> bool {
    let Some(core) = name.strip_prefix('.').and_then(|n| n.strip_suffix(".part")) else {
        return false;
    };
    let Some((hash, size)) = core.split_once('-') else {
        return false;
    };
    hash.len() == 32
        && hash.bytes().all(|b| b.is_ascii_hexdigit())
        && !size.is_empty()
        && size.bytes().all(|b| b.is_ascii_digit())
}

/// Remove our `.part` files under `inbox/<contact>/` that were last written
/// more than `max_age` before `now` and are not in `active`. `max_age` zero
/// means "keep forever". Nothing else is ever touched.
pub fn sweep_partials_in(
    inbox: &Path,
    max_age: Duration,
    active: &HashSet<PathBuf>,
    now: std::time::SystemTime,
) -> usize {
    if max_age.is_zero() {
        return 0;
    }
    let Ok(contacts) = std::fs::read_dir(inbox) else {
        return 0;
    };
    let mut removed = 0;
    for dir in contacts.flatten() {
        let dir = dir.path();
        if !dir.is_dir() {
            continue;
        }
        let Ok(files) = std::fs::read_dir(&dir) else {
            continue;
        };
        for f in files.flatten() {
            let p = f.path();
            let name = f.file_name().to_string_lossy().into_owned();
            if !is_our_part_name(&name) || active.contains(&p) {
                continue;
            }
            let Ok(meta) = f.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            let Ok(modified) = meta.modified() else {
                continue;
            };
            if now.duration_since(modified).is_ok_and(|age| age > max_age)
                && std::fs::remove_file(&p).is_ok()
            {
                removed += 1;
            }
        }
    }
    removed
}

struct PartGuard<'a> {
    set: &'a Mutex<HashMap<PathBuf, Arc<Notify>>>,
    path: PathBuf,
}

impl Drop for PartGuard<'_> {
    fn drop(&mut self) {
        self.set.lock().unwrap().remove(&self.path);
    }
}

fn contact_leaf(dir: &Path) -> String {
    dir.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

async fn finish_stream(tx: &mut BoxTx) {
    tx.finish();
    // Let the peer read the answer before the stream can be torn down.
    let _ = tokio::time::timeout(Duration::from_secs(10), tx.stopped()).await;
}

async fn wait_cancel(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

fn reject_text(r: RejectReason) -> String {
    match r {
        RejectReason::TooLarge => "the file is larger than the receiver accepts",
        RejectReason::NoSpace => "the receiver does not have enough free disk space",
        RejectReason::NotAllowed => {
            "the other side has not registered you: ask them to add your contact code"
        }
        RejectReason::Busy => "the receiver is busy; try again in a moment",
        RejectReason::BadName => "the receiver refused the file name",
        RejectReason::BadRequest => "the receiver did not understand the request (version?)",
    }
    .to_owned()
}

fn describe_dial_error(e: &IrohClientError) -> String {
    match e {
        IrohClientError::Unreachable(m) => format!(
            "cannot reach the other side: {m}. Is their Miasma running? Run `miasma netcheck` to \
             see what this network allows."
        ),
        other => other.to_string(),
    }
}

/// BLAKE3 of the file and its size, in a blocking thread. `None` if cancelled.
async fn hash_file(
    path: &Path,
    cancel: watch::Receiver<bool>,
) -> std::io::Result<Option<(String, u64)>> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut f = std::fs::File::open(&path)?;
        let mut h = blake3::Hasher::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut total = 0u64;
        loop {
            if *cancel.borrow() {
                return Ok(None);
            }
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            total += n as u64;
        }
        Ok(Some((h.finalize().to_hex().to_string(), total)))
    })
    .await
    .map_err(std::io::Error::other)?
}

/// A hasher primed with the first `len` bytes of `path`. `None` if cancelled.
fn hash_prefix(
    path: &Path,
    len: u64,
    cancel: &watch::Receiver<bool>,
) -> std::io::Result<Option<blake3::Hasher>> {
    use std::io::Read;
    let f = std::fs::File::open(path)?;
    let mut f = f.take(len);
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        if *cancel.borrow() {
            return Ok(None);
        }
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
    if total != len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "partial file shorter than expected",
        ));
    }
    Ok(Some(h))
}

/// Move `part` to `dir/name`, never replacing an existing file: if the name is
/// taken, `name (1).ext`, `name (2).ext`, ... The target is reserved with
/// `create_new` first, so two arrivals cannot pick the same name.
pub fn place_without_overwrite(part: &Path, dir: &Path, name: &str) -> std::io::Result<PathBuf> {
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 && name.len() - i <= 16 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    for n in 0..10_000u32 {
        let candidate = if n == 0 {
            name.to_owned()
        } else {
            format!("{stem} ({n}){ext}")
        };
        // Stay inside the name budget when a suffix was added.
        let candidate = if candidate.len() > crate::transfer::manifest::MAX_NAME_BYTES {
            continue;
        } else {
            candidate
        };
        let target = dir.join(&candidate);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
        {
            Ok(f) => {
                drop(f);
                if let Err(e) = std::fs::rename(part, &target) {
                    let _ = std::fs::remove_file(&target);
                    return Err(e);
                }
                return Ok(target);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("too many files with this name"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_overwrite_adds_suffix_and_keeps_extension() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..3 {
            let part = dir.path().join(format!(".p{i}.part"));
            std::fs::write(&part, format!("data{i}")).unwrap();
            let p = place_without_overwrite(&part, dir.path(), "報告書.pdf").unwrap();
            let want = match i {
                0 => "報告書.pdf".to_owned(),
                n => format!("報告書 ({n}).pdf"),
            };
            assert_eq!(p.file_name().unwrap().to_string_lossy(), want);
            assert_eq!(std::fs::read_to_string(&p).unwrap(), format!("data{i}"));
        }
    }

    #[test]
    fn limiter_is_bounded_and_throttles() {
        let mut l = Limiter::new();
        let id = [1u8; 32];
        let allowed = (0..20).filter(|_| l.allow(id)).count();
        assert_eq!(allowed, 5);
        for i in 0..5000u32 {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_be_bytes());
            l.allow(k);
        }
        assert!(l.buckets.len() <= Limiter::CAP);
    }
}
