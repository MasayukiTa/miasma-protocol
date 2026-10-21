//! Persistent (or, in ephemeral mode, in-memory) chat state.
//!
//! Per contact, two files in the `chat` folder, named by a keyed hash of the
//! contact's ID so the names say nothing:
//!
//! * `<stem>.sess` : one small encrypted document (`ChatSessions`) with the
//!   ratchet session, the counters that make delivery idempotent (next
//!   sequence number to send, which sequence numbers were already applied) and
//!   a short summary (message count, time of the last message).
//! * `<stem>.msgs` : an encrypted append-only record log (`ChatHistory`) of
//!   finished messages. Reads stream the log; a page is built in a bounded
//!   window and nothing loads a whole conversation.
//!
//! Messages that are queued or being sent live in the outbox
//! ([`super::outbox`]) and are merged into the first page of the history.
//!
//! **Ephemeral mode** (`history_save = false`): finished messages are kept
//! only in a bounded in-memory ring (oldest dropped first) and never written;
//! sessions and the outbox are still written (encrypted) so that a restart
//! does not lose the ability to decrypt or to deliver.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use tracing::warn;

use super::{
    anchor::{Anchor, Check, NO_FILE},
    crypto::{file_stem, Rd, Session},
    proto::MAX_TEXT_BYTES,
};
use crate::state_crypto::{
    self, doc, Label, LogReader, LogRewrite, LogWriter, StateError, StateKeys,
};

/// Newest messages kept per conversation in the saved history.
pub const DEFAULT_MAX_MESSAGES: usize = 10_000;
/// Cap of the ephemeral ring, in bytes of text plus bookkeeping.
pub const EPHEMERAL_BYTES: usize = 2 * 1024 * 1024;
/// Largest history page.
pub const MAX_PAGE: usize = 200;
/// Text bytes a history page may hold in memory.
pub const MAX_PAGE_BYTES: usize = 1024 * 1024;
const PEER_CACHE: usize = 32;
const WRITER_CACHE: usize = 8;
const MAX_ABOVE: usize = 256;
const MAX_SEEN_EKS: usize = 16;
const MAX_RECENT_ENV: usize = 64;
const ENTRY_OVERHEAD: usize = 112;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{0}")]
    State(#[from] StateError),
    #[error("the outbox is full")]
    OutboxFull,
    #[error("damaged chat state")]
    Damaged,
}

/// Settings of the stores (from `[chat]` and `[privacy]`).
#[derive(Debug, Clone)]
pub struct StoreSettings {
    /// Write finished messages to disk. False = ephemeral ring in memory.
    pub history_save: bool,
    /// Messages older than this many days are removed (0 = keep).
    pub retention_days: u64,
    pub max_messages_per_conversation: usize,
    pub ephemeral_bytes: usize,
    pub outbox_max: usize,
    pub outbox_max_per_contact: usize,
    /// Text bytes the outbox may hold.
    pub outbox_bytes: usize,
    pub outbox_expiry_days: u64,
    /// A read receipt that could not be delivered within this many
    /// milliseconds is dropped.
    pub receipt_expiry_ms: u64,
    /// Tests and benchmarks only: do not write the session state per message;
    /// the caller writes it with `flush_all`. Off in the service.
    pub defer_flush: bool,
}

/// Default life of a read receipt that cannot be delivered: one day.
pub const DEFAULT_RECEIPT_EXPIRY_MS: u64 = 24 * 3_600_000;

impl Default for StoreSettings {
    fn default() -> Self {
        Self {
            history_save: true,
            retention_days: 0,
            max_messages_per_conversation: DEFAULT_MAX_MESSAGES,
            ephemeral_bytes: EPHEMERAL_BYTES,
            outbox_max: 500,
            outbox_max_per_contact: 100,
            outbox_bytes: 1024 * 1024,
            outbox_expiry_days: 30,
            receipt_expiry_ms: DEFAULT_RECEIPT_EXPIRY_MS,
            defer_flush: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgState {
    Queued,
    Sending,
    Delivered,
    Failed,
    Received,
    /// Delivered and the contact has read it. Only ever derived for display
    /// from the contact's receipts; a saved message is never stored as read.
    Read,
}

impl MsgState {
    fn code(self) -> u8 {
        match self {
            Self::Queued => 0,
            Self::Sending => 1,
            Self::Delivered | Self::Read => 2,
            Self::Failed => 3,
            Self::Received => 4,
        }
    }
    fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => Self::Queued,
            1 => Self::Sending,
            2 => Self::Delivered,
            3 => Self::Failed,
            4 => Self::Received,
            _ => return None,
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sending => "sending",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::Received => "received",
            Self::Read => "read",
        }
    }
}

/// One message as stored and shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    /// Position in the conversation (grows with every recorded message;
    /// 0 for a message that is still in the outbox).
    pub ord: u64,
    pub outgoing: bool,
    pub id: [u8; 16],
    pub seq: u64,
    pub sent_ms: u64,
    /// When this side recorded it (received, or finished sending).
    pub at_ms: u64,
    pub state: MsgState,
    pub reason: Option<String>,
    /// For a message still waiting: when the last delivery attempt started
    /// (0 = none yet). Not stored.
    pub tried_ms: u64,
    pub text: String,
}

impl StoredMessage {
    fn cost(&self) -> usize {
        self.text.len() + ENTRY_OVERHEAD
    }

    fn encode(&self) -> Vec<u8> {
        let reason = self.reason.as_deref().unwrap_or("");
        let mut v = Vec::with_capacity(64 + self.text.len() + reason.len());
        v.push(1);
        v.extend_from_slice(&self.ord.to_be_bytes());
        v.push(u8::from(self.outgoing));
        v.extend_from_slice(&self.id);
        v.extend_from_slice(&self.seq.to_be_bytes());
        v.extend_from_slice(&self.sent_ms.to_be_bytes());
        v.extend_from_slice(&self.at_ms.to_be_bytes());
        v.push(self.state.code());
        v.push(reason.len().min(255) as u8);
        v.extend_from_slice(&reason.as_bytes()[..reason.len().min(255)]);
        v.extend_from_slice(&(self.text.len() as u16).to_be_bytes());
        v.extend_from_slice(self.text.as_bytes());
        v
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Rd::new(b);
        if r.u8().ok()? != 1 {
            return None;
        }
        let ord = r.u64().ok()?;
        let outgoing = r.u8().ok()? != 0;
        let id = r.arr::<16>().ok()?;
        let seq = r.u64().ok()?;
        let sent_ms = r.u64().ok()?;
        let at_ms = r.u64().ok()?;
        let state = MsgState::from_code(r.u8().ok()?)?;
        let rl = r.u8().ok()? as usize;
        let reason = if rl == 0 {
            None
        } else {
            Some(std::str::from_utf8(r.bytes(rl).ok()?).ok()?.to_owned())
        };
        let n = r.u16().ok()? as usize;
        if n > MAX_TEXT_BYTES {
            return None;
        }
        let text = std::str::from_utf8(r.bytes(n).ok()?).ok()?.to_owned();
        if !r.done() {
            return None;
        }
        Some(Self {
            ord,
            outgoing,
            id,
            seq,
            sent_ms,
            at_ms,
            state,
            reason,
            tried_ms: 0,
            text,
        })
    }
}

/// A message to record (the store assigns `ord`).
pub struct NewMessage {
    pub outgoing: bool,
    pub id: [u8; 16],
    pub seq: u64,
    pub sent_ms: u64,
    pub at_ms: u64,
    pub state: MsgState,
    pub reason: Option<String>,
    pub text: String,
}

// ─── Per-contact state ───────────────────────────────────────────────────────

/// What is remembered about one contact besides the messages.
pub struct PeerState {
    pub peer: [u8; 32],
    /// Last sequence number given to a message for this contact.
    pub send_seq: u64,
    /// Every received sequence number up to here has been applied.
    pub recv_floor: u64,
    /// Applied sequence numbers above the floor (sorted, bounded).
    pub recv_above: Vec<u64>,
    /// First-flight keys of sessions already used (a replayed old first
    /// message must not start a session again).
    pub seen_eks: VecDeque<[u8; 32]>,
    /// Envelope IDs applied lately: a retry of the same envelope after a lost
    /// acknowledgement is answered as a duplicate.
    pub recent_env: VecDeque<[u8; 16]>,
    /// Summary: messages in the history, time of the last one.
    pub count: u64,
    pub last_ms: u64,
    pub session: Option<Session>,
    /// The contact has read our messages up to this number (from its receipts).
    pub read_up_to: u64,
    /// We have told the contact that we read its messages up to this number.
    pub read_reported: u64,
    /// Read receipts are switched off for this contact (on by default).
    pub receipts_off: bool,
}

const PEER_VERSION: u8 = 2;

impl PeerState {
    pub fn new(peer: [u8; 32]) -> Self {
        Self {
            peer,
            send_seq: 0,
            recv_floor: 0,
            recv_above: Vec::new(),
            seen_eks: VecDeque::new(),
            recent_env: VecDeque::new(),
            count: 0,
            last_ms: 0,
            session: None,
            read_up_to: 0,
            read_reported: 0,
            receipts_off: false,
        }
    }

    /// The highest sequence number received from the contact so far.
    pub fn max_recv_seq(&self) -> u64 {
        self.recv_above
            .last()
            .copied()
            .unwrap_or(0)
            .max(self.recv_floor)
    }

    pub fn next_seq(&mut self) -> u64 {
        self.send_seq += 1;
        self.send_seq
    }

    /// True when `seq` has not been applied yet.
    pub fn is_new_seq(&self, seq: u64) -> bool {
        seq > self.recv_floor && self.recv_above.binary_search(&seq).is_err()
    }

    /// Record `seq` as applied. A gap that stays open while more than
    /// [`MAX_ABOVE`] later numbers arrive is given up on (the floor moves
    /// over it) so the set stays bounded.
    pub fn mark_seq(&mut self, seq: u64) {
        if seq <= self.recv_floor {
            return;
        }
        if let Err(i) = self.recv_above.binary_search(&seq) {
            self.recv_above.insert(i, seq);
        }
        while self.recv_above.len() > MAX_ABOVE {
            self.recv_floor = self.recv_above.remove(0);
        }
        while let Some(&first) = self.recv_above.first() {
            if first == self.recv_floor + 1 {
                self.recv_floor = first;
                self.recv_above.remove(0);
            } else {
                break;
            }
        }
    }

    pub fn remember_ek(&mut self, ek: [u8; 32]) {
        if !self.seen_eks.contains(&ek) {
            if self.seen_eks.len() >= MAX_SEEN_EKS {
                self.seen_eks.pop_front();
            }
            self.seen_eks.push_back(ek);
        }
    }

    pub fn remember_envelope(&mut self, id: [u8; 16]) {
        if self.recent_env.len() >= MAX_RECENT_ENV {
            self.recent_env.pop_front();
        }
        self.recent_env.push_back(id);
    }

    fn to_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let mut w = zeroize::Zeroizing::new(Vec::with_capacity(1024));
        w.push(PEER_VERSION);
        w.extend_from_slice(&self.peer);
        w.extend_from_slice(&self.send_seq.to_be_bytes());
        w.extend_from_slice(&self.recv_floor.to_be_bytes());
        w.extend_from_slice(&(self.recv_above.len() as u16).to_be_bytes());
        for s in &self.recv_above {
            w.extend_from_slice(&s.to_be_bytes());
        }
        w.push(self.seen_eks.len() as u8);
        for k in &self.seen_eks {
            w.extend_from_slice(k);
        }
        w.push(self.recent_env.len() as u8);
        for k in &self.recent_env {
            w.extend_from_slice(k);
        }
        w.extend_from_slice(&self.count.to_be_bytes());
        w.extend_from_slice(&self.last_ms.to_be_bytes());
        match &self.session {
            Some(s) => {
                let sb = s.to_bytes();
                w.push(1);
                w.extend_from_slice(&(sb.len() as u32).to_be_bytes());
                w.extend_from_slice(&sb);
            }
            None => w.push(0),
        }
        w.extend_from_slice(&self.read_up_to.to_be_bytes());
        w.extend_from_slice(&self.read_reported.to_be_bytes());
        w.push(u8::from(self.receipts_off));
        w
    }

    fn from_bytes(b: &[u8]) -> Option<Self> {
        let mut r = Rd::new(b);
        // Version 1 had no receipt fields; its files still open.
        let version = r.u8().ok()?;
        if version != 1 && version != PEER_VERSION {
            return None;
        }
        let peer = r.arr::<32>().ok()?;
        let send_seq = r.u64().ok()?;
        let recv_floor = r.u64().ok()?;
        let na = r.u16().ok()? as usize;
        if na > MAX_ABOVE {
            return None;
        }
        let mut recv_above = Vec::with_capacity(na);
        for _ in 0..na {
            recv_above.push(r.u64().ok()?);
        }
        let ne = r.u8().ok()? as usize;
        if ne > MAX_SEEN_EKS {
            return None;
        }
        let mut seen_eks = VecDeque::new();
        for _ in 0..ne {
            seen_eks.push_back(r.arr::<32>().ok()?);
        }
        let nv = r.u8().ok()? as usize;
        if nv > MAX_RECENT_ENV {
            return None;
        }
        let mut recent_env = VecDeque::new();
        for _ in 0..nv {
            recent_env.push_back(r.arr::<16>().ok()?);
        }
        let count = r.u64().ok()?;
        let last_ms = r.u64().ok()?;
        let session = match r.u8().ok()? {
            0 => None,
            1 => {
                let n = r.u32().ok()? as usize;
                if n > 256 * 1024 {
                    return None;
                }
                Some(Session::from_bytes(r.bytes(n).ok()?).ok()?)
            }
            _ => return None,
        };
        let (read_up_to, read_reported, receipts_off) = if version >= 2 {
            let up = r.u64().ok()?;
            let rep = r.u64().ok()?;
            let off = match r.u8().ok()? {
                0 => false,
                1 => true,
                _ => return None,
            };
            (up, rep, off)
        } else {
            (0, 0, false)
        };
        if !r.done() {
            return None;
        }
        Some(Self {
            peer,
            send_seq,
            recv_floor,
            recv_above,
            seen_eks,
            recent_env,
            count,
            last_ms,
            session,
            read_up_to,
            read_reported,
            receipts_off,
        })
    }
}

/// One line of the conversation list.
#[derive(Debug, Clone)]
pub struct ConversationSummary {
    pub peer: [u8; 32],
    pub count: u64,
    pub last_ms: u64,
}

// ─── The store ───────────────────────────────────────────────────────────────

struct PeerSlot {
    state: PeerState,
    dirty: bool,
    used: u64,
    /// Next `ord` of the saved log; known after the first scan.
    next_ord: Option<u64>,
}

struct RingEntry {
    peer: [u8; 32],
    msg: StoredMessage,
}

struct Inner {
    peers: HashMap<[u8; 32], PeerSlot>,
    writers: HashMap<[u8; 32], (LogWriter, u64)>,
    ring: VecDeque<RingEntry>,
    ring_bytes: usize,
    ring_next: HashMap<[u8; 32], u64>,
    tick: u64,
    /// Contacts whose session file was found to be older than the one written
    /// last; the engine settles each once ([`ChatStore::take_rollback`]).
    rolled_back: HashSet<[u8; 32]>,
}

pub struct ChatStore {
    dir: PathBuf,
    keys: Arc<StateKeys>,
    own_id: [u8; 32],
    settings: StoreSettings,
    inner: Mutex<Inner>,
    /// The record kept outside the data folder (see [`super::anchor`]).
    anchor: Option<Anchor>,
}

impl ChatStore {
    pub fn open(
        dir: &Path,
        keys: Arc<StateKeys>,
        own_id: [u8; 32],
        settings: StoreSettings,
    ) -> Result<Self, StoreError> {
        std::fs::create_dir_all(dir).map_err(StateError::Io)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            keys,
            own_id,
            settings,
            inner: Mutex::new(Inner {
                peers: HashMap::new(),
                writers: HashMap::new(),
                ring: VecDeque::new(),
                ring_bytes: 0,
                ring_next: HashMap::new(),
                tick: 0,
                rolled_back: HashSet::new(),
            }),
            anchor: None,
        })
    }

    /// Keep a record outside the data folder of which session file was
    /// written last, and drop a session whose file turns out to be older.
    pub fn with_anchor(mut self, anchor: Anchor) -> Self {
        self.anchor = Some(anchor);
        self
    }

    /// Test hook: write `peer` if changed and forget it, so the next use
    /// reads the file again.
    #[cfg(test)]
    pub(crate) fn evict_for_test(&self, peer: &[u8; 32]) {
        let mut g = self.inner.lock().unwrap();
        if let Some(s) = g.peers.remove(peer) {
            if s.dirty {
                let _ = self.write_peer(&s.state);
            }
        }
    }

    /// True once if the session file of `peer` was found older than the last
    /// one written (the session was dropped and the send counter raised).
    /// The caller then voids what was sealed on the dropped session.
    pub fn take_rollback(&self, peer: &[u8; 32]) -> bool {
        let mut g = self.inner.lock().unwrap();
        self.slot(&mut g, peer);
        g.rolled_back.remove(peer)
    }

    pub fn settings(&self) -> &StoreSettings {
        &self.settings
    }

    pub fn own_id(&self) -> [u8; 32] {
        self.own_id
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The keys that protect the saved documents (for sibling documents).
    pub fn keys(&self) -> &Arc<StateKeys> {
        &self.keys
    }

    fn stem(&self, peer: &[u8; 32]) -> String {
        file_stem(&self.own_id, peer)
    }

    fn history_path(&self, peer: &[u8; 32]) -> PathBuf {
        crate::paths::chat_history_file(&self.dir, &self.stem(peer))
    }

    fn session_path(&self, peer: &[u8; 32]) -> PathBuf {
        crate::paths::chat_session_file(&self.dir, &self.stem(peer))
    }

    // ── Per-contact state ────────────────────────────────────────────────────

    /// The state of `peer` from disk, and whether it is older than the last
    /// one written (then the session is dropped and the send counter raised).
    fn load_peer(&self, peer: &[u8; 32]) -> (PeerState, bool) {
        let path = self.session_path(peer);
        let mut found = None;
        let mut disk = NO_FILE;
        if path.exists() {
            match doc::read_document_fingerprinted(&self.keys, Label::ChatSessions, &path) {
                Ok((bytes, fp)) => match PeerState::from_bytes(&bytes) {
                    Some(s) if &s.peer == peer => {
                        found = Some(s);
                        disk = fp;
                    }
                    _ => warn!("a chat session file is damaged; it was set aside"),
                },
                Err(e) => warn!("a chat session file cannot be read ({e}); it was set aside"),
            }
            if found.is_none() {
                let _ = state_crypto::set_aside(&path);
            }
        }
        let mut state = found.unwrap_or_else(|| PeerState::new(*peer));
        let mut behind = false;
        if let Some(a) = &self.anchor {
            if let Check::Behind { send_seq_floor } = a.check(peer, disk, state.send_seq) {
                // Older than what was written last: its keys may have been
                // used. A new session starts, and no number is used twice.
                state.session = None;
                state.send_seq = state.send_seq.max(send_seq_floor);
                behind = true;
            }
        }
        (state, behind)
    }

    fn slot<'a>(&self, g: &'a mut Inner, peer: &[u8; 32]) -> &'a mut PeerSlot {
        g.tick += 1;
        let tick = g.tick;
        if !g.peers.contains_key(peer) {
            if g.peers.len() >= PEER_CACHE {
                // Evict the least recently used contact, writing it first.
                let victim = g
                    .peers
                    .iter()
                    .min_by_key(|(_, s)| s.used)
                    .map(|(k, _)| *k)
                    .expect("cache is not empty");
                if let Some(s) = g.peers.remove(&victim) {
                    if s.dirty {
                        let _ = self.write_peer(&s.state);
                    }
                }
                g.writers.remove(&victim);
            }
            let (state, behind) = self.load_peer(peer);
            if behind {
                g.rolled_back.insert(*peer);
            }
            g.peers.insert(
                *peer,
                PeerSlot {
                    state,
                    dirty: behind,
                    used: tick,
                    next_ord: None,
                },
            );
        }
        let s = g.peers.get_mut(peer).expect("just inserted");
        s.used = tick;
        s
    }

    fn write_peer(&self, st: &PeerState) -> Result<(), StoreError> {
        let bytes = st.to_bytes();
        let path = self.session_path(&st.peer);
        let Some(anchor) = &self.anchor else {
            doc::write_document(&self.keys, Label::ChatSessions, &path, &bytes)?;
            return Ok(());
        };
        // The record is written before the file is replaced, so a file that
        // can have been used to send is always known to the record.
        let sealed = doc::seal(
            &self.keys,
            Label::ChatSessions,
            &doc::context_of(&path),
            &bytes,
        )?;
        let fp = doc::fingerprint(&sealed);
        anchor.before_write(&st.peer, fp, st.send_seq);
        doc::write_sealed(&path, &sealed, true)?;
        anchor.after_write(&st.peer, fp, st.send_seq);
        Ok(())
    }

    /// Run `f` on the state of `peer`; the state is marked changed and written
    /// by the next [`flush_peer`](Self::flush_peer).
    pub fn with_peer<R>(&self, peer: &[u8; 32], f: impl FnOnce(&mut PeerState) -> R) -> R {
        let mut g = self.inner.lock().unwrap();
        let slot = self.slot(&mut g, peer);
        slot.dirty = true;
        f(&mut slot.state)
    }

    /// As [`with_peer`](Self::with_peer) for a read that changes nothing.
    pub fn peek_peer<R>(&self, peer: &[u8; 32], f: impl FnOnce(&PeerState) -> R) -> R {
        let mut g = self.inner.lock().unwrap();
        let slot = self.slot(&mut g, peer);
        f(&slot.state)
    }

    /// Write the state of `peer` if it changed (durable).
    pub fn flush_peer(&self, peer: &[u8; 32]) -> Result<(), StoreError> {
        if self.settings.defer_flush {
            return Ok(());
        }
        let mut g = self.inner.lock().unwrap();
        if let Some(s) = g.peers.get_mut(peer) {
            if s.dirty {
                self.write_peer(&s.state)?;
                s.dirty = false;
            }
        }
        Ok(())
    }

    /// Write every changed state.
    pub fn flush_all(&self) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        for s in g.peers.values_mut() {
            if s.dirty {
                self.write_peer(&s.state)?;
                s.dirty = false;
            }
        }
        Ok(())
    }

    // ── History ──────────────────────────────────────────────────────────────

    /// Stream the saved log of `peer`, oldest record first.
    fn scan(&self, peer: &[u8; 32], mut f: impl FnMut(StoredMessage)) {
        let path = self.history_path(peer);
        let Ok(Some(mut r)) = LogReader::open(&self.keys, Label::ChatHistory, &path) else {
            return;
        };
        while let Ok(Some(rec)) = r.next_record() {
            if let Some(m) = StoredMessage::decode(&rec) {
                f(m);
            }
        }
    }

    fn next_ord(&self, g: &mut Inner, peer: &[u8; 32]) -> u64 {
        if !self.settings.history_save {
            let n = g.ring_next.entry(*peer).or_insert(1);
            let v = *n;
            *n += 1;
            return v;
        }
        let known = self.slot(g, peer).next_ord;
        let next = match known {
            Some(n) => n,
            None => {
                let mut max = 0u64;
                let mut count = 0u64;
                self.scan(peer, |m| {
                    max = max.max(m.ord);
                    count += 1;
                });
                let slot = self.slot(g, peer);
                slot.state.count = count;
                slot.dirty = true;
                max + 1
            }
        };
        self.slot(g, peer).next_ord = Some(next + 1);
        next
    }

    /// Record a finished message. Returns its `ord`.
    pub fn record(&self, peer: &[u8; 32], m: NewMessage, durable: bool) -> Result<u64, StoreError> {
        let mut g = self.inner.lock().unwrap();
        let ord = self.next_ord(&mut g, peer);
        let msg = StoredMessage {
            ord,
            outgoing: m.outgoing,
            id: m.id,
            seq: m.seq,
            sent_ms: m.sent_ms,
            at_ms: m.at_ms,
            state: m.state,
            reason: m.reason,
            tried_ms: 0,
            text: m.text,
        };
        {
            let slot = self.slot(&mut g, peer);
            slot.state.count += 1;
            slot.state.last_ms = slot.state.last_ms.max(msg.at_ms);
            slot.dirty = true;
        }
        if !self.settings.history_save {
            g.ring_bytes += msg.cost();
            g.ring.push_back(RingEntry { peer: *peer, msg });
            while g.ring_bytes > self.settings.ephemeral_bytes {
                match g.ring.pop_front() {
                    Some(old) => {
                        g.ring_bytes = g.ring_bytes.saturating_sub(old.msg.cost());
                        let slot = self.slot(&mut g, &old.peer);
                        slot.state.count = slot.state.count.saturating_sub(1);
                    }
                    None => break,
                }
            }
            return Ok(ord);
        }
        let rec = msg.encode();
        self.append_record(&mut g, peer, &rec, durable && !self.settings.defer_flush)?;
        let too_many = {
            let slot = self.slot(&mut g, peer);
            slot.state.count as usize
                > self.settings.max_messages_per_conversation
                    + self.settings.max_messages_per_conversation / 10
        };
        if too_many {
            self.rewrite(&mut g, peer, |m, _| {
                // Keep the newest `max` by ord.
                m.ord + (self.settings.max_messages_per_conversation as u64) > ord
            })?;
        }
        Ok(ord)
    }

    fn append_record(
        &self,
        g: &mut Inner,
        peer: &[u8; 32],
        rec: &[u8],
        durable: bool,
    ) -> Result<(), StoreError> {
        g.tick += 1;
        let tick = g.tick;
        if !g.writers.contains_key(peer) {
            if g.writers.len() >= WRITER_CACHE {
                if let Some(victim) = g
                    .writers
                    .iter()
                    .min_by_key(|(_, (_, used))| *used)
                    .map(|(k, _)| *k)
                {
                    g.writers.remove(&victim);
                }
            }
            let w =
                LogWriter::open_append(&self.keys, Label::ChatHistory, &self.history_path(peer))?;
            g.writers.insert(*peer, (w, tick));
        }
        let entry = g.writers.get_mut(peer).expect("just inserted");
        entry.1 = tick;
        let res = if durable {
            entry.0.append_durable(rec)
        } else {
            entry.0.append(rec)
        };
        if let Err(e) = res {
            g.writers.remove(peer);
            return Err(e.into());
        }
        Ok(())
    }

    /// Rewrite the saved log keeping the records `keep` accepts (it is also
    /// given the running index).
    fn rewrite(
        &self,
        g: &mut Inner,
        peer: &[u8; 32],
        mut keep: impl FnMut(&StoredMessage, u64) -> bool,
    ) -> Result<u64, StoreError> {
        g.writers.remove(peer);
        let path = self.history_path(peer);
        let tmp = path.with_extension("msgs.tmp");
        let Some(mut reader) = LogReader::open(&self.keys, Label::ChatHistory, &path)? else {
            return Ok(0);
        };
        let mut out = LogRewrite::begin(&self.keys, Label::ChatHistory, &path, &tmp)?;
        let mut kept = 0u64;
        let mut idx = 0u64;
        while let Some(rec) = reader.next_record()? {
            if let Some(m) = StoredMessage::decode(&rec) {
                if keep(&m, idx) {
                    out.append(&rec)?;
                    kept += 1;
                }
                idx += 1;
            }
        }
        drop(reader);
        out.commit()?;
        let slot = self.slot(g, peer);
        slot.state.count = kept;
        slot.dirty = true;
        Ok(kept)
    }

    /// A page of the conversation: up to `limit` messages with `ord < before`
    /// (the newest ones when `before` is `None`), oldest first. Messages still
    /// in the outbox are appended to the page that reaches the newest end.
    pub fn history(
        &self,
        peer: &[u8; 32],
        before: Option<u64>,
        limit: usize,
        pending: Vec<StoredMessage>,
    ) -> Vec<StoredMessage> {
        let limit = limit.clamp(1, MAX_PAGE);
        let upper = before.unwrap_or(u64::MAX);
        let mut win: Vec<StoredMessage> = Vec::with_capacity(limit.min(64));
        let mut take = |m: StoredMessage| {
            if m.ord >= upper {
                return;
            }
            if win.len() == limit && m.ord < win[0].ord {
                return;
            }
            let at = win.partition_point(|x| x.ord < m.ord);
            if win.get(at).is_some_and(|x| x.ord == m.ord) {
                return;
            }
            win.insert(at, m);
            if win.len() > limit {
                win.remove(0);
            }
        };
        if self.settings.history_save {
            // Hold the lock so a concurrent append is not half-visible.
            let _g = self.inner.lock().unwrap();
            self.scan(peer, &mut take);
        } else {
            let g = self.inner.lock().unwrap();
            for e in g.ring.iter().filter(|e| &e.peer == peer) {
                take(e.msg.clone());
            }
        }
        let mut bytes: usize = win.iter().map(|m| m.cost()).sum();
        while bytes > MAX_PAGE_BYTES && win.len() > 1 {
            bytes -= win.remove(0).cost();
        }
        if before.is_none() {
            for p in pending {
                if !win.iter().any(|m| m.id == p.id) {
                    win.push(p);
                }
            }
        }
        win
    }

    /// Remove one message from the saved history. True when it was there.
    pub fn delete_message(&self, peer: &[u8; 32], id: &[u8; 16]) -> Result<bool, StoreError> {
        let mut g = self.inner.lock().unwrap();
        if !self.settings.history_save {
            let before = g.ring.len();
            let mut freed = 0usize;
            g.ring.retain(|e| {
                let hit = &e.peer == peer && &e.msg.id == id;
                if hit {
                    freed += e.msg.cost();
                }
                !hit
            });
            g.ring_bytes = g.ring_bytes.saturating_sub(freed);
            let removed = g.ring.len() != before;
            if removed {
                let slot = self.slot(&mut g, peer);
                slot.state.count = slot.state.count.saturating_sub(1);
                slot.dirty = true;
            }
            return Ok(removed);
        }
        let mut found = false;
        self.rewrite(&mut g, peer, |m, _| {
            if &m.id == id {
                found = true;
                false
            } else {
                true
            }
        })?;
        Ok(found)
    }

    /// Remove the whole saved history of `peer` (the session and the
    /// counters stay, so replay protection is not lost).
    pub fn delete_conversation(&self, peer: &[u8; 32]) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        g.writers.remove(peer);
        let path = self.history_path(peer);
        if path.exists() {
            state_crypto::overwrite_and_remove(&path).map_err(StateError::Io)?;
        }
        let mut freed = 0usize;
        g.ring.retain(|e| {
            let hit = &e.peer == peer;
            if hit {
                freed += e.msg.cost();
            }
            !hit
        });
        g.ring_bytes = g.ring_bytes.saturating_sub(freed);
        g.ring_next.remove(peer);
        let slot = self.slot(&mut g, peer);
        slot.state.count = 0;
        slot.state.last_ms = 0;
        slot.next_ord = Some(1);
        slot.dirty = true;
        Ok(())
    }

    /// Drop saved messages older than the retention. Returns how many.
    pub fn sweep_retention(&self, now_ms: u64) -> usize {
        if self.settings.retention_days == 0 {
            return 0;
        }
        let cutoff = now_ms.saturating_sub(self.settings.retention_days.saturating_mul(86_400_000));
        let mut removed = 0usize;
        for c in self.conversations() {
            let mut g = self.inner.lock().unwrap();
            if !self.settings.history_save {
                let before = g.ring.len();
                let mut freed = 0usize;
                g.ring.retain(|e| {
                    let old = e.peer == c.peer && e.msg.at_ms < cutoff;
                    if old {
                        freed += e.msg.cost();
                    }
                    !old
                });
                g.ring_bytes = g.ring_bytes.saturating_sub(freed);
                removed += before - g.ring.len();
                continue;
            }
            let mut total = 0usize;
            let mut kept = 0usize;
            if self
                .rewrite(&mut g, &c.peer, |m, _| {
                    total += 1;
                    let k = m.at_ms >= cutoff;
                    if k {
                        kept += 1;
                    }
                    k
                })
                .is_ok()
            {
                removed += total - kept;
            }
        }
        removed
    }

    /// Every conversation that has a session file, newest activity first.
    pub fn conversations(&self) -> Vec<ConversationSummary> {
        let mut out: Vec<ConversationSummary> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                let path = e.path();
                if !crate::paths::is_chat_session_file(&path) {
                    continue;
                }
                if let Ok(bytes) = doc::read_document(&self.keys, Label::ChatSessions, &path) {
                    if let Some(st) = PeerState::from_bytes(&bytes) {
                        out.push(ConversationSummary {
                            peer: st.peer,
                            count: st.count,
                            last_ms: st.last_ms,
                        });
                    }
                }
            }
        }
        // Fresher values for contacts held in memory (not yet written).
        let g = self.inner.lock().unwrap();
        for (peer, slot) in g.peers.iter() {
            match out.iter_mut().find(|c| &c.peer == peer) {
                Some(c) => {
                    c.count = slot.state.count;
                    c.last_ms = slot.state.last_ms;
                }
                None => out.push(ConversationSummary {
                    peer: *peer,
                    count: slot.state.count,
                    last_ms: slot.state.last_ms,
                }),
            }
        }
        out.sort_by(|a, b| b.last_ms.cmp(&a.last_ms));
        out
    }

    /// Bytes held by the ephemeral ring (tests).
    pub fn ring_bytes(&self) -> usize {
        self.inner.lock().unwrap().ring_bytes
    }

    /// Whether the history of `peer` has a file (tests).
    pub fn history_file_exists(&self, peer: &[u8; 32]) -> bool {
        self.history_path(peer).exists()
    }

    /// Settle everything and release file handles.
    pub fn close(&self) {
        let _ = self.flush_all();
        self.inner.lock().unwrap().writers.clear();
    }
}

/// Entry point for the fuzz targets only (`--cfg fuzzing`, set by cargo-fuzz):
/// parses a per-peer state document. Not compiled in any other build.
#[cfg(fuzzing)]
pub fn fuzz_peer_state(b: &[u8]) -> bool {
    PeerState::from_bytes(b).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Arc<StateKeys> {
        Arc::new(StateKeys::from_master_key(&rand::random()).unwrap())
    }

    fn msg(i: u64, outgoing: bool) -> NewMessage {
        NewMessage {
            outgoing,
            id: {
                let mut id = [0u8; 16];
                id[..8].copy_from_slice(&i.to_be_bytes());
                id
            },
            seq: i,
            sent_ms: 1_000 + i,
            at_ms: 2_000 + i,
            state: if outgoing {
                MsgState::Delivered
            } else {
                MsgState::Received
            },
            reason: None,
            text: format!("message number {i} こんにちは"),
        }
    }

    fn store(dir: &Path, save: bool) -> ChatStore {
        let s = StoreSettings {
            history_save: save,
            ..StoreSettings::default()
        };
        ChatStore::open(&dir.join("chat"), keys_for(dir), [9u8; 32], s).unwrap()
    }

    // One key per test directory so a reopened store can read what it wrote.
    fn keys_for(dir: &Path) -> Arc<StateKeys> {
        let marker = dir.join("k");
        let seed: [u8; 32] = match std::fs::read(&marker) {
            Ok(b) => b.try_into().unwrap(),
            Err(_) => {
                let s: [u8; 32] = rand::random();
                std::fs::write(&marker, s).unwrap();
                s
            }
        };
        Arc::new(StateKeys::from_master_key(&seed).unwrap())
    }

    #[test]
    fn peer_state_round_trips_and_rejects_damage() {
        let mut p = PeerState::new([5u8; 32]);
        p.next_seq();
        p.mark_seq(1);
        p.mark_seq(5);
        p.remember_ek([6u8; 32]);
        p.remember_envelope([7u8; 16]);
        p.count = 3;
        let b = p.to_bytes();
        let q = PeerState::from_bytes(&b).unwrap();
        assert_eq!(
            (q.send_seq, q.recv_floor, q.recv_above.clone()),
            (1, 1, vec![5])
        );
        assert_eq!(q.seen_eks.len(), 1);
        for n in 0..b.len() {
            assert!(PeerState::from_bytes(&b[..n]).is_none(), "prefix {n}");
        }
    }

    #[test]
    fn old_session_files_without_receipt_fields_still_open() {
        let mut p = PeerState::new([5u8; 32]);
        p.send_seq = 4;
        p.read_up_to = 3;
        p.read_reported = 2;
        p.receipts_off = true;
        let bytes = p.to_bytes();
        let back = PeerState::from_bytes(&bytes).unwrap();
        assert_eq!(
            (back.read_up_to, back.read_reported, back.receipts_off),
            (3, 2, true)
        );
        // The same state as version 1 wrote it: the receipt fields are missing.
        let mut v1 = bytes.to_vec();
        v1[0] = 1;
        v1.truncate(v1.len() - 17);
        let old = PeerState::from_bytes(&v1).unwrap();
        assert_eq!(old.send_seq, 4);
        assert_eq!(
            (old.read_up_to, old.read_reported, old.receipts_off),
            (0, 0, false)
        );
        // Damage is still refused.
        let mut bad = bytes.to_vec();
        bad.push(0);
        assert!(PeerState::from_bytes(&bad).is_none());
        let last = bytes.len() - 1;
        let mut bad_flag = bytes.to_vec();
        bad_flag[last] = 7;
        assert!(PeerState::from_bytes(&bad_flag).is_none());
    }

    #[test]
    fn sequence_numbers_apply_once_and_stay_bounded() {
        let mut p = PeerState::new([1u8; 32]);
        for s in [1u64, 2, 4, 3, 7] {
            assert!(p.is_new_seq(s), "{s}");
            p.mark_seq(s);
            assert!(!p.is_new_seq(s), "{s} again");
        }
        assert_eq!(p.recv_floor, 4);
        assert_eq!(p.recv_above, vec![7]);
        // A gap that never fills is given up on once the set would grow.
        let mut q = PeerState::new([1u8; 32]);
        for s in 2..2000u64 {
            q.mark_seq(s);
        }
        assert!(q.recv_above.len() <= MAX_ABOVE);
        assert!(q.recv_floor > 1000);
        assert!(!q.is_new_seq(1500));
    }

    #[test]
    fn history_pages_newest_first_and_is_stable_across_reopen() {
        let d = tempfile::tempdir().unwrap();
        let peer = [3u8; 32];
        {
            let st = store(d.path(), true);
            for i in 1..=120u64 {
                st.record(&peer, msg(i, i % 2 == 0), false).unwrap();
            }
            st.close();
        }
        let st = store(d.path(), true);
        let page = st.history(&peer, None, 50, vec![]);
        assert_eq!(page.len(), 50);
        assert_eq!(page.first().unwrap().seq, 71);
        assert_eq!(page.last().unwrap().seq, 120);
        assert!(page.windows(2).all(|w| w[0].ord < w[1].ord));
        let older = st.history(&peer, Some(page[0].ord), 50, vec![]);
        assert_eq!(older.last().unwrap().seq, 70);
        assert_eq!(older.first().unwrap().seq, 21);
        let oldest = st.history(&peer, Some(older[0].ord), 50, vec![]);
        assert_eq!(oldest.len(), 20);
        assert_eq!(oldest.first().unwrap().seq, 1);
        // New messages continue the numbering after a reopen.
        let ord = st.record(&peer, msg(121, true), false).unwrap();
        assert_eq!(ord, 121);
    }

    #[test]
    fn stored_bytes_do_not_contain_the_plaintext() {
        let d = tempfile::tempdir().unwrap();
        let peer = [4u8; 32];
        let st = store(d.path(), true);
        let mut m = msg(1, true);
        m.text = "UNIQUE-MARKER-STRING-0xC0FFEE".into();
        st.record(&peer, m, true).unwrap();
        st.with_peer(&peer, |p| p.count += 0);
        st.close();
        for e in std::fs::read_dir(d.path().join("chat")).unwrap().flatten() {
            let b = std::fs::read(e.path()).unwrap();
            assert!(
                !b.windows(8).any(|w| w == b"UNIQUE-M"),
                "plaintext found in {:?}",
                e.file_name()
            );
        }
    }

    #[test]
    fn ephemeral_mode_keeps_messages_in_memory_only_and_bounded() {
        let d = tempfile::tempdir().unwrap();
        let peer = [5u8; 32];
        let s = StoreSettings {
            history_save: false,
            ephemeral_bytes: 64 * 1024,
            ..StoreSettings::default()
        };
        let st = ChatStore::open(&d.path().join("chat"), keys_for(d.path()), [9u8; 32], s).unwrap();
        for i in 1..=2000u64 {
            st.record(&peer, msg(i, false), false).unwrap();
        }
        assert!(st.ring_bytes() <= 64 * 1024);
        assert!(!st.history_file_exists(&peer));
        let page = st.history(&peer, None, 10, vec![]);
        assert_eq!(page.last().unwrap().seq, 2000);
        // Nothing with a message in it is on disk.
        st.close();
        for e in std::fs::read_dir(d.path().join("chat")).unwrap().flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            assert!(!n.ends_with("msgs"), "{n}");
        }
    }

    #[test]
    fn delete_one_message_and_delete_all() {
        let d = tempfile::tempdir().unwrap();
        let peer = [6u8; 32];
        let st = store(d.path(), true);
        for i in 1..=5u64 {
            st.record(&peer, msg(i, true), false).unwrap();
        }
        let id3 = msg(3, true).id;
        assert!(st.delete_message(&peer, &id3).unwrap());
        assert!(!st.delete_message(&peer, &id3).unwrap());
        let seqs: Vec<u64> = st
            .history(&peer, None, 50, vec![])
            .iter()
            .map(|m| m.seq)
            .collect();
        assert_eq!(seqs, vec![1, 2, 4, 5]);
        st.delete_conversation(&peer).unwrap();
        assert!(st.history(&peer, None, 50, vec![]).is_empty());
        assert!(!st.history_file_exists(&peer));
        // Numbering starts over but the counters of the pair are untouched.
        assert_eq!(st.record(&peer, msg(9, true), false).unwrap(), 1);
    }

    #[test]
    fn retention_removes_old_messages() {
        let d = tempfile::tempdir().unwrap();
        let peer = [7u8; 32];
        let s = StoreSettings {
            retention_days: 1,
            ..StoreSettings::default()
        };
        let st = ChatStore::open(&d.path().join("chat"), keys_for(d.path()), [9u8; 32], s).unwrap();
        let now = 10 * 86_400_000u64;
        for (i, age_days) in [(1u64, 5u64), (2, 3), (3, 0)] {
            let mut m = msg(i, false);
            m.at_ms = now - age_days * 86_400_000;
            st.record(&peer, m, false).unwrap();
        }
        st.flush_all().unwrap();
        assert_eq!(st.sweep_retention(now), 2);
        let left = st.history(&peer, None, 50, vec![]);
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].seq, 3);
    }

    #[test]
    fn a_conversation_is_trimmed_to_its_cap() {
        let d = tempfile::tempdir().unwrap();
        let peer = [8u8; 32];
        let s = StoreSettings {
            max_messages_per_conversation: 50,
            ..StoreSettings::default()
        };
        let st = ChatStore::open(&d.path().join("chat"), keys_for(d.path()), [9u8; 32], s).unwrap();
        for i in 1..=200u64 {
            st.record(&peer, msg(i, false), false).unwrap();
        }
        let all = st.history(&peer, None, 200, vec![]);
        assert!(all.len() <= 56 && all.len() >= 50, "{}", all.len());
        assert_eq!(all.last().unwrap().seq, 200);
    }

    #[test]
    fn session_documents_survive_reopen_and_list_as_conversations() {
        let d = tempfile::tempdir().unwrap();
        let peer = [2u8; 32];
        {
            let st = store(d.path(), true);
            st.with_peer(&peer, |p| {
                p.next_seq();
                p.last_ms = 42;
            });
            st.flush_peer(&peer).unwrap();
        }
        let st = store(d.path(), true);
        assert_eq!(st.peek_peer(&peer, |p| p.send_seq), 1);
        let list = st.conversations();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].peer, peer);
        assert_eq!(list[0].last_ms, 42);
        let _ = keys();
    }
}
