//! The push service: the receiving side (accepts connections from contacts),
//! the sending side (per-contact sequential queues), and the bookkeeping the
//! IPC layer exposes.
//!
//! Identity: the only identity of a peer is `Connection::remote_id()`, proven
//! by the QUIC/TLS handshake. Nothing in a message is believed about who the
//! peer is.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufWriter},
    sync::{watch, Semaphore},
};
use tracing::{debug, info};

use super::{
    contact::{fingerprint, ContactCode},
    proto::{
        self, Done, Header, ProtoError, RejectReason, Reply, CLOSE_BAD_REQUEST, CLOSE_NOT_ALLOWED,
        CLOSE_OK, PROTOCOL_VERSION,
    },
    state::{
        error_kind, now_ms, Board, Direction, History, HistoryEntry, PushState, PushTransferInfo,
        RateMeter, MAX_ACTIVE,
    },
    store::{Contact, ContactError, ContactStore, ContactUpdate},
};
use crate::{
    config::PushConfig,
    transfer::manifest::sanitize_file_name,
    transport::iroh_direct::{IrohClientError, IrohNode, PushConnectionHandler, PUSH_ALPN},
};

/// Sending reads and the receiver's writes use chunks of this size.
const CHUNK: usize = 256 * 1024;
/// Streams (files) served on one connection before it is closed.
const MAX_STREAMS_PER_CONNECTION: usize = 10_000;
const MAX_QUEUED_PER_SERVICE: usize = MAX_ACTIVE;
/// How often old partial files are looked for (the first look is at start).
const PART_SWEEP_EVERY: Duration = Duration::from_secs(24 * 3600);

type FreeSpaceFn = Arc<dyn Fn(&Path) -> Option<u64> + Send + Sync>;

/// Runtime settings (derived from `[push]` in `config.toml`).
#[derive(Clone)]
pub struct PushSettings {
    pub inbox_dir: PathBuf,
    pub max_file_size: u64,
    pub min_free_bytes: u64,
    pub max_concurrent_inbound: usize,
    /// No byte moved for this long => the transfer is abandoned.
    pub idle_timeout: Duration,
    /// How long to wait for the other side's reply to the header and for the
    /// final verification (hashing a multi-GB file takes a while).
    pub reply_timeout: Duration,
    /// Waits between retries after a dropped connection.
    pub retry_delays: Vec<Duration>,
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
            reply_timeout: Duration::from_secs(600),
            retry_delays: vec![
                Duration::from_secs(2),
                Duration::from_secs(5),
                Duration::from_secs(10),
            ],
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

struct Job {
    id: String,
    path: PathBuf,
    cancel: watch::Receiver<bool>,
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
    node: Arc<IrohNode>,
    inbound_slots: Arc<Semaphore>,
    active_parts: Mutex<HashSet<PathBuf>>,
    limiter: Mutex<Limiter>,
    queues: Mutex<HashMap<String, ContactQueue>>,
    shutdown: watch::Sender<bool>,
}

/// Why one attempt to send failed.
enum AttemptError {
    /// Worth retrying (resume picks up where it stopped). `kind` is the stable
    /// [`error_kind`] shown if the retries run out.
    Retry(&'static str, String),
    /// Retry once from scratch (the receiver's hash check failed).
    Restart(String),
    Fatal(String),
    Rejected(RejectReason),
    Cancelled,
}

impl PushService {
    /// Create the service and install it as the PUSH_ALPN handler of `node`.
    pub fn start(data_dir: &Path, node: Arc<IrohNode>, settings: PushSettings) -> Arc<Self> {
        let contacts = Arc::new(ContactStore::open(data_dir));
        let own_id = node.endpoint_id();
        let (shutdown, _) = watch::channel(false);
        let svc = Arc::new(Self {
            inbound_slots: Arc::new(Semaphore::new(settings.max_concurrent_inbound)),
            settings,
            contacts,
            board: Board::new(),
            history: History::open(data_dir),
            own_id,
            node: node.clone(),
            active_parts: Mutex::new(HashSet::new()),
            limiter: Mutex::new(Limiter::new()),
            queues: Mutex::new(HashMap::new()),
            shutdown,
        });
        node.set_push_handler(svc.clone());
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
        info!(
            fingerprint = %fingerprint(&own_id),
            contacts = svc.contacts.list().len(),
            "trusted-contact push is on (inbox: {})",
            svc.settings.inbox_dir.display()
        );
        svc
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
        let active = self.active_parts.lock().unwrap().clone();
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
        let active = self.active_parts.lock().unwrap().clone();
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

    /// Queue `path` for `selector`'s contact. Returns the transfer id.
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
        self.board.update(&id, |i| i.source_path = Some(shown_path));
        let start_worker = {
            let mut q = self.queues.lock().unwrap();
            let cq = q.entry(contact.id.clone()).or_default();
            cq.jobs.push_back(Job {
                id: id.clone(),
                path: path.to_path_buf(),
                cancel,
            });
            !std::mem::replace(&mut cq.running, true)
        };
        if start_worker {
            let me = self.clone();
            let cid = contact.id.clone();
            tokio::spawn(async move { me.worker(cid).await });
        }
        Ok(id)
    }

    async fn worker(self: Arc<Self>, contact_id: String) {
        let mut conn: Option<Connection> = None;
        loop {
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
            c.close(CLOSE_OK.into(), b"done");
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
        self.board.update(id, |i| {
            i.state = state;
            i.error = error;
            i.reject_reason = reason.map(|r| r.as_str().to_owned());
            i.error_kind = kind.map(str::to_owned);
            i.rate_bps = 0;
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

    async fn run_job(&self, contact_id: &str, conn: &mut Option<Connection>, mut job: Job) {
        let id = job.id.clone();
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

        // Hash first: the header carries it, and it is the resume key.
        self.board.update(&id, |i| i.state = PushState::Preparing);
        let (hash, size) = match hash_file(&job.path, job.cancel.clone()).await {
            Ok(Some(v)) => v,
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
        };
        self.board.update(&id, |i| i.size = size);
        let name = job
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        let mut attempt = 0usize;
        let mut restarted = false;
        loop {
            if *job.cancel.borrow() {
                return self.finish(&id, PushState::Cancelled, None, None);
            }
            self.board.update(&id, |i| i.state = PushState::Connecting);
            let c = match self.ensure_conn(conn, &target).await {
                Ok(c) => c,
                Err(e) => {
                    let kind = match e {
                        IrohClientError::Unreachable(_) => error_kind::UNREACHABLE,
                        _ => error_kind::CONNECTION_LOST,
                    };
                    return self.finish_kind(
                        &id,
                        PushState::Failed,
                        Some(describe_dial_error(&e)),
                        None,
                        Some(kind),
                    );
                }
            };
            let res = self
                .attempt_send(&c, &id, &job.path, &name, size, &hash, &mut job.cancel)
                .await;
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
                    c.close(proto::CLOSE_CANCELLED.into(), b"cancelled");
                    return self.finish(&id, PushState::Cancelled, None, None);
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
                    *conn = None;
                    let Some(delay) = self.settings.retry_delays.get(attempt).copied() else {
                        return self.finish_kind(&id, PushState::Failed, Some(m), None, Some(kind));
                    };
                    attempt += 1;
                    debug!("push {id}: {m}; retrying in {delay:?}");
                    self.board.update(&id, |i| {
                        i.error = Some(m);
                        i.error_kind = Some(kind.to_owned());
                    });
                    let mut cancel = job.cancel.clone();
                    tokio::select! {
                        _ = tokio::time::sleep(delay) => {}
                        _ = wait_cancel(&mut cancel) => {}
                    }
                }
            }
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
        let c = self.node.connect_alpn(target, PUSH_ALPN).await?;
        *slot = Some(c.clone());
        Ok(c)
    }

    /// If the connection was closed by the receiver as "not allowed".
    fn closed_as_not_allowed(conn: &Connection) -> bool {
        matches!(
            conn.close_reason(),
            Some(iroh::endpoint::ConnectionError::ApplicationClosed(c))
                if u64::from(c.error_code) == u64::from(CLOSE_NOT_ALLOWED)
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn attempt_send(
        &self,
        conn: &Connection,
        id: &str,
        path: &Path,
        name: &str,
        size: u64,
        hash: &str,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<Option<String>, AttemptError> {
        let idle = self.settings.idle_timeout;
        let broken = |conn: &Connection, what: &str, e: String| {
            if Self::closed_as_not_allowed(conn) {
                AttemptError::Rejected(RejectReason::NotAllowed)
            } else {
                AttemptError::Retry(error_kind::CONNECTION_LOST, format!("{what}: {e}"))
            }
        };
        let (mut tx, mut rx) =
            match tokio::time::timeout(Duration::from_secs(30), conn.open_bi()).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(broken(conn, "open stream", e.to_string())),
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
        let reply: Reply =
            match tokio::time::timeout(self.settings.reply_timeout, proto::read_frame(&mut rx))
                .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => return Err(broken(conn, "no reply", e.to_string())),
                Err(_) => {
                    return Err(AttemptError::Retry(
                        error_kind::TIMED_OUT,
                        "the other side did not reply".into(),
                    ))
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

        self.board.update(id, |i| {
            i.state = PushState::Sending;
            i.bytes = offset;
            i.error = None;
            i.error_kind = None;
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
                w = tokio::time::timeout(idle, AsyncWriteExt::write_all(&mut tx, &buf[..n])) => match w {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(broken(conn, "send", e.to_string())),
                    Err(_) => return Err(AttemptError::Retry(error_kind::TIMED_OUT, "the other side stopped accepting data".into())),
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
        let _ = tx.finish();
        self.board.update(id, |i| {
            i.state = PushState::Verifying;
            i.rate_bps = 0;
        });
        let done: Done = tokio::select! {
            _ = wait_cancel(cancel) => return Err(AttemptError::Cancelled),
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
        conn: &Connection,
        contact: Contact,
        mut tx: SendStream,
        mut rx: RecvStream,
    ) -> bool {
        let header: Header =
            match tokio::time::timeout(Duration::from_secs(30), proto::read_frame(&mut rx)).await {
                Ok(Ok(h)) => h,
                _ => {
                    conn.close(CLOSE_BAD_REQUEST.into(), b"");
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
            RxEnd::Cancelled => {
                self.finish(&tid, PushState::Cancelled, None, None);
                conn.close(proto::CLOSE_CANCELLED.into(), b"cancelled");
                false
            }
        }
    }

    async fn reject(&self, tx: &mut SendStream, reason: RejectReason) -> bool {
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
        conn: &Connection,
        contact: &Contact,
        name: &str,
        header: &Header,
        tid: &str,
        tx: &mut SendStream,
        rx: &mut RecvStream,
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
        if !self.active_parts.lock().unwrap().insert(part.clone()) {
            return RxEnd::Rejected(RejectReason::Busy);
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
        tx: &mut SendStream,
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
    async fn handle(&self, conn: Connection) {
        self.serve_borrowed(conn).await
    }
}

impl PushService {
    async fn serve_borrowed(&self, conn: Connection) {
        // Looked up for every stream: a contact removed or switched off
        // mid-connection stops being served at once.
        let remote = *conn.remote_id().as_bytes();
        let mut shutdown = self.shutdown.subscribe();
        for _ in 0..MAX_STREAMS_PER_CONNECTION {
            let contact = match self.contacts.by_endpoint(&remote) {
                Some(c) if c.allow_receive => c,
                _ => {
                    let loud = self.limiter.lock().unwrap().allow(remote);
                    if loud {
                        debug!(peer = %fingerprint(&remote), "push refused: not a contact that may send");
                    }
                    conn.close(CLOSE_NOT_ALLOWED.into(), b"");
                    return;
                }
            };
            let (tx, rx) = tokio::select! {
                _ = shutdown.changed() => break,
                r = tokio::time::timeout(self.settings.idle_timeout, conn.accept_bi()) => match r {
                    Ok(Ok(s)) => s,
                    _ => break,
                }
            };
            if !self.receive_one(&conn, contact, tx, rx).await {
                return;
            }
        }
        conn.close(CLOSE_OK.into(), b"done");
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
}

/// The inbound stream broke. If the sender closed the connection on purpose
/// (`CLOSE_CANCELLED`), delete the partial file: nobody will resume it. Any
/// other loss (network, the sender's process died) keeps the partial for a
/// resume; the retention sweep removes it if the sender never comes back.
async fn rx_broke(
    conn: &Connection,
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
async fn closed_by_peer_cancel(conn: &Connection) -> bool {
    let reason = match conn.close_reason() {
        Some(r) => Some(r),
        None => tokio::time::timeout(Duration::from_millis(500), conn.closed())
            .await
            .ok(),
    };
    matches!(
        reason,
        Some(iroh::endpoint::ConnectionError::ApplicationClosed(c))
            if u64::from(c.error_code) == u64::from(proto::CLOSE_CANCELLED)
    )
}

/// Stable kind of a sender-side `Fatal` message (they are our own texts).
fn fatal_kind(m: &str) -> Option<&'static str> {
    if m.starts_with("cannot read the file") || m.starts_with("the file changed") {
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
    set: &'a Mutex<HashSet<PathBuf>>,
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

async fn finish_stream(tx: &mut SendStream) {
    let _ = tx.finish();
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
