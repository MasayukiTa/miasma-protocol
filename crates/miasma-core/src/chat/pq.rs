//! Hybrid (X25519 + ML-KEM-768) upgrade of a private-conversation
//! session. Compiled only with the `pqc` cargo feature; in a build that has it,
//! nothing below acts unless `privacy.pqc_mode` is `prefer` (the default) or
//! `require`.
//!
//! This wiring has not been reviewed by an outside cryptographer. See
//! `docs/pqc-session-upgrade.md` for the design, the limits and what is not
//! covered.
//!
//! # Why an upgrade inside the session, not a new first flight
//!
//! The first message of a conversation is sealed while the peer may be
//! offline (see `crypto.rs`), so a key exchange that needs an answer cannot be
//! part of it. The session therefore starts exactly as before, and the hybrid
//! exchange runs inside it afterwards, as ordinary sealed records. A message
//! sent after both sides finished is protected by the ratchet message key
//! **and** the hybrid key (`crypto::layer_key`); the ratchet itself is never
//! touched, so the session stays a valid classical session at every moment.
//!
//! # Old and new builds
//!
//! The offer, the exchange and the confirmations are four record kinds
//! (`0x20..=0x23`) inside the sealed envelope. A build that does not know them
//! either acknowledges and sets them aside (`Record::Unknown`) or answers
//! "bad request" for that one record, which this side reads as "the peer has
//! no hybrid exchange". Neither answer changes the session or the delivery of
//! messages, and the envelope bytes, the frames and the acknowledgements are
//! the ones every earlier build writes.
//!
//! # Roles and order
//!
//! Each side sends its offer first (the capability offer of
//! `protocol::capability`). When both offers are known and agree on the hybrid
//! suite, the side with the smaller endpoint ID starts the exchange of
//! `protocol::hybrid`; its two messages travel in fragments of at most
//! [`FRAGMENT_PAYLOAD`] bytes (`protocol::fragment`), one fragment per record,
//! so no record grows beyond the smallest padding bucket. Both sides then send
//! a key-confirmation tag. A side starts layering its messages only after it
//! has verified the peer's tag.
//!
//! # Policy
//!
//! * `prefer`: messages are never held back. If the peer offers nothing, or
//!   not the hybrid suite, the session stays classical and the state is
//!   `classical` with a stated reason (also counted in the daemon status).
//! * `require`: messages to a contact wait until the session is `hybrid`.
//!   When the peer is found not to offer the hybrid suite (or the exchange
//!   fails) they fail on this device with a reason, and nothing is sent in the
//!   classical session. This is a local decision; the peer is unaffected.
//!
//! # Memory
//!
//! Per contact: one small record (a few hundred bytes plus the session key).
//! Fragment reassembly is bounded by `protocol::fragment` (the total length is
//! capped at the size of the largest exchange message and at most 8 messages
//! are assembled at once per contact); at most [`MAX_PEERS`] contacts are kept
//! in memory; the replay guard keeps [`REPLAY_CAPACITY`] hashes. The session
//! key is wiped when its record is dropped.

use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, AtomicU8, Ordering},
        Arc, Mutex,
    },
};

use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use tracing::{debug, warn};
use zeroize::{Zeroize, Zeroizing};

use super::{
    crypto::{file_stem, Rd},
    ipc::PqcCounts,
};
use crate::{
    config::PqcMode,
    protocol::{
        capability::{
            negotiate_offer, Capabilities, Requirements, FEATURE_FRAGMENTATION,
            SUITE_HYBRID_X25519_MLKEM768,
        },
        hybrid::{
            fragment_message, Config as KexConfig, Established, HybridError, Initiator,
            MessageReassembler, Mode as KexMode, ReplayGuard, Responder, SUITE_ID_HYBRID,
        },
    },
    state_crypto::{self, doc, Label, StateKeys},
};

/// Record kinds inside the sealed envelope (the pairwise kinds are 1 and 2,
/// group chat uses `0x10..=0x12`).
pub const KIND_OFFER: u8 = 0x20;
pub const KIND_INIT: u8 = 0x21;
pub const KIND_RESP: u8 = 0x22;
pub const KIND_CONFIRM: u8 = 0x23;

/// True for a record kind this module handles.
pub fn is_pq_kind(k: u8) -> bool {
    (KIND_OFFER..=KIND_CONFIRM).contains(&k)
}

/// Payload bytes of one fragment: the fragment header (23 bytes) plus the kind
/// byte stay below the 512-byte padding bucket.
pub const FRAGMENT_PAYLOAD: usize = 400;
/// How long a side waits for the peer's offer after its own was delivered.
pub const OFFER_WAIT_MS: u64 = 15_000;
/// How long a side waits for the next message of the exchange once everything
/// it had to send was delivered.
pub const EXCHANGE_TIMEOUT_MS: u64 = 120_000;
/// Times the initiator starts the exchange again before giving up.
pub const MAX_EXCHANGE_TRIES: u8 = 5;
/// A "classical" decision is taken again after this long (the peer may have
/// been updated or switched the setting on).
pub const RETRY_CLASSICAL_MS: u64 = 3_600_000;
/// A failed exchange is tried again after this long.
pub const RETRY_FAILED_MS: u64 = 600_000;
/// Contacts kept in memory.
pub const MAX_PEERS: usize = 64;
/// First messages remembered by the replay guard.
pub const REPLAY_CAPACITY: usize = 64;
/// Longest offer accepted: the capability fixed part plus the extension cap.
pub const MAX_OFFER_BYTES: usize = 12 + 256;
const MAX_OUTQ: usize = 16;

/// Stable words for the reason of a `classical` or `failed` state.
pub mod reason {
    pub const NONE: u8 = 0;
    /// The peer offered nothing, or not the hybrid suite.
    pub const PEER_NO_HYBRID: u8 = 1;
    /// The peer answered the offer with "bad request" (an older build).
    pub const PEER_OLD_BUILD: u8 = 2;
    pub const EXCHANGE_FAILED: u8 = 3;
    pub const TIMEOUT: u8 = 4;
    pub const CONFIRM_MISMATCH: u8 = 5;

    pub fn word(code: u8) -> Option<&'static str> {
        Some(match code {
            PEER_NO_HYBRID => "peer_no_hybrid",
            PEER_OLD_BUILD => "peer_old_build",
            EXCHANGE_FAILED => "exchange_failed",
            TIMEOUT => "exchange_timeout",
            CONFIRM_MISMATCH => "confirm_mismatch",
            _ => return None,
        })
    }
}

/// Failure reasons given to a message under `require` (stable, shown to the
/// person through the usual failed-message reason).
pub const FAIL_NO_HYBRID: &str = "pqc_peer_no_hybrid";
pub const FAIL_EXCHANGE: &str = "pqc_failed";

// ─── Counters (numbers only, no peer identifiers) ───────────────────────────

static HYBRID_SESSIONS: AtomicU64 = AtomicU64::new(0);
static CLASSICAL_ONLY: AtomicU64 = AtomicU64::new(0);
static REFUSED: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU64 = AtomicU64::new(0);
static OFFERS_SENT: AtomicU64 = AtomicU64::new(0);
static OFFERS_RECEIVED: AtomicU64 = AtomicU64::new(0);

/// What this process has done with the hybrid upgrade so far.
pub fn counts() -> PqcCounts {
    PqcCounts {
        hybrid_sessions: HYBRID_SESSIONS.load(Ordering::Relaxed),
        classical_only: CLASSICAL_ONLY.load(Ordering::Relaxed),
        refused: REFUSED.load(Ordering::Relaxed),
        failed: FAILED.load(Ordering::Relaxed),
        offers_sent: OFFERS_SENT.load(Ordering::Relaxed),
        offers_received: OFFERS_RECEIVED.load(Ordering::Relaxed),
    }
}

// ─── Secret ─────────────────────────────────────────────────────────────────

#[cfg(test)]
thread_local! {
    static KEY_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// A 32-byte secret that is wiped when dropped.
struct Key([u8; 32]);

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        {
            assert!(self.0.iter().all(|b| *b == 0));
            KEY_DROPS.with(|c| c.set(c.get() + 1));
        }
    }
}

// ─── What goes out ──────────────────────────────────────────────────────────

/// One record to seal and deliver: the kind byte and its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub plain: Vec<u8>,
}

impl Outgoing {
    fn new(kind: u8, body: &[u8]) -> Self {
        let mut plain = Vec::with_capacity(1 + body.len());
        plain.push(kind);
        plain.extend_from_slice(body);
        Self { plain }
    }

    pub fn kind(&self) -> u8 {
        self.plain[0]
    }
}

/// What the delivery loop does next for a contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pass {
    /// Seal and deliver this record, report the result with
    /// `ChatCore::pq_sent`, then ask again.
    Send(Outgoing),
    /// Messages may go out now.
    Proceed,
    /// `require`: the exchange is not finished; hold the messages and ask again
    /// shortly.
    Hold,
    /// `require`: the contact cannot be reached with the hybrid exchange; fail
    /// the waiting messages with this reason.
    Refuse(&'static str),
}

/// What the peer did with a record we delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    Delivered,
    /// The peer answered "bad request": it does not know the record.
    NotUnderstood,
}

/// What a person may be shown about one contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqView {
    /// `off`, `pending`, `hybrid`, `classical` or `failed`.
    pub state: &'static str,
    pub reason: Option<&'static str>,
}

// ─── State of one contact ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Nothing has been delivered yet.
    New = 0,
    /// Our offer is delivered; the peer's is awaited.
    Offered = 1,
    /// The session stays classical.
    Classical = 2,
    /// The hybrid suite is agreed; the exchange runs.
    Kex = 4,
    /// Both tags verified: messages are layered.
    Active = 5,
    Failed = 6,
}

impl Phase {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::New,
            1 => Self::Offered,
            2 => Self::Classical,
            4 => Self::Kex,
            5 => Self::Active,
            6 => Self::Failed,
            _ => return None,
        })
    }
}

struct Peer {
    /// The session this state belongs to (`Session::origin_ek`).
    sid: [u8; 32],
    phase: Phase,
    reason: u8,
    decided_ms: u64,
    our_offer: Vec<u8>,
    peer_offer: Vec<u8>,
    /// When our offer was delivered; 0 = not yet.
    offered_ms: u64,
    key: Option<Key>,
    own_tag: [u8; 32],
    peer_tag: [u8; 32],
    peer_confirmed: bool,
    own_confirm_sent: bool,
    // Memory only: a restart starts the unfinished exchange again.
    outq: VecDeque<Outgoing>,
    initiator: Option<Initiator>,
    handshake_id: u64,
    /// Since when everything we had to send is delivered and the peer's next
    /// message is awaited; 0 = not waiting.
    waiting_since_ms: u64,
    tries: u8,
    reasm: Option<MessageReassembler>,
    dirty: bool,
}

const PEER_VERSION: u8 = 1;
const F_PEER_CONFIRMED: u8 = 1;
const F_OWN_CONFIRM_SENT: u8 = 2;
const F_HAS_KEY: u8 = 4;

impl Peer {
    fn fresh(sid: [u8; 32]) -> Self {
        Self {
            sid,
            phase: Phase::New,
            reason: reason::NONE,
            decided_ms: 0,
            our_offer: Capabilities::current().encode(),
            peer_offer: Vec::new(),
            offered_ms: 0,
            key: None,
            own_tag: [0; 32],
            peer_tag: [0; 32],
            peer_confirmed: false,
            own_confirm_sent: false,
            outq: VecDeque::new(),
            initiator: None,
            handshake_id: 0,
            waiting_since_ms: 0,
            tries: 0,
            reasm: None,
            dirty: false,
        }
    }

    fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Zeroizing::new(Vec::with_capacity(512));
        w.push(PEER_VERSION);
        w.extend_from_slice(&self.sid);
        w.push(self.phase as u8);
        w.push(self.reason);
        w.extend_from_slice(&self.decided_ms.to_be_bytes());
        w.extend_from_slice(&self.offered_ms.to_be_bytes());
        let mut flags = 0u8;
        if self.peer_confirmed {
            flags |= F_PEER_CONFIRMED;
        }
        if self.own_confirm_sent {
            flags |= F_OWN_CONFIRM_SENT;
        }
        if self.key.is_some() {
            flags |= F_HAS_KEY;
        }
        w.push(flags);
        w.extend_from_slice(&(self.our_offer.len() as u16).to_be_bytes());
        w.extend_from_slice(&self.our_offer);
        w.extend_from_slice(&(self.peer_offer.len() as u16).to_be_bytes());
        w.extend_from_slice(&self.peer_offer);
        if let Some(k) = &self.key {
            w.extend_from_slice(&k.0);
            w.extend_from_slice(&self.own_tag);
            w.extend_from_slice(&self.peer_tag);
        }
        w
    }

    fn from_bytes(b: &[u8]) -> Option<Self> {
        let mut r = Rd::new(b);
        if r.u8().ok()? != PEER_VERSION {
            return None;
        }
        let sid = r.arr::<32>().ok()?;
        let phase = Phase::from_u8(r.u8().ok()?)?;
        let reason = r.u8().ok()?;
        let decided_ms = r.u64().ok()?;
        let offered_ms = r.u64().ok()?;
        let flags = r.u8().ok()?;
        if flags & !(F_PEER_CONFIRMED | F_OWN_CONFIRM_SENT | F_HAS_KEY) != 0 {
            return None;
        }
        let n = r.u16().ok()? as usize;
        if n > MAX_OFFER_BYTES {
            return None;
        }
        let our_offer = r.bytes(n).ok()?.to_vec();
        let n = r.u16().ok()? as usize;
        if n > MAX_OFFER_BYTES {
            return None;
        }
        let peer_offer = r.bytes(n).ok()?.to_vec();
        let (key, own_tag, peer_tag) = if flags & F_HAS_KEY != 0 {
            let k = r.arr::<32>().ok()?;
            (Some(Key(k)), r.arr::<32>().ok()?, r.arr::<32>().ok()?)
        } else {
            (None, [0; 32], [0; 32])
        };
        if !r.done() {
            return None;
        }
        Some(Self {
            sid,
            phase,
            reason,
            decided_ms,
            our_offer,
            peer_offer,
            offered_ms,
            key,
            own_tag,
            peer_tag,
            peer_confirmed: flags & F_PEER_CONFIRMED != 0,
            own_confirm_sent: flags & F_OWN_CONFIRM_SENT != 0,
            outq: VecDeque::new(),
            initiator: None,
            handshake_id: 0,
            waiting_since_ms: 0,
            tries: 0,
            reasm: None,
            dirty: false,
        })
    }

    fn wipe_exchange(&mut self) {
        self.key = None;
        self.own_tag.zeroize();
        self.peer_tag.zeroize();
        self.peer_confirmed = false;
        self.own_confirm_sent = false;
        self.outq.clear();
        self.initiator = None;
        self.reasm = None;
        self.waiting_since_ms = 0;
    }
}

/// What a decision needs to know besides the contact's record.
struct Env {
    own: [u8; 32],
    peer: [u8; 32],
    mode: PqcMode,
    now: u64,
}

impl Env {
    fn we_initiate(&self) -> bool {
        self.own < self.peer
    }
}

fn kex_mode(mode: PqcMode) -> KexMode {
    if mode == PqcMode::Require {
        KexMode::Strict
    } else {
        KexMode::Compatibility
    }
}

/// The exchange configuration. The initiator identity carries the session ID,
/// so the key belongs to this session and no other.
fn kex_config(p: &Peer, env: &Env) -> Option<KexConfig> {
    let local = Capabilities::decode(&p.our_offer).ok()?;
    let remote = Capabilities::decode(&p.peer_offer).ok()?;
    let (initiator_id, responder_id) = if env.we_initiate() {
        let mut i = env.own.to_vec();
        i.extend_from_slice(&p.sid);
        (i, env.peer.to_vec())
    } else {
        let mut i = env.peer.to_vec();
        i.extend_from_slice(&p.sid);
        (i, env.own.to_vec())
    };
    Some(KexConfig {
        mode: kex_mode(env.mode),
        local,
        remote,
        initiator_id,
        responder_id,
    })
}

fn mark_classical(p: &mut Peer, env: &Env, why: u8) {
    p.wipe_exchange();
    p.phase = Phase::Classical;
    p.reason = why;
    p.decided_ms = env.now;
    p.dirty = true;
    CLASSICAL_ONLY.fetch_add(1, Ordering::Relaxed);
    if env.mode == PqcMode::Require {
        REFUSED.fetch_add(1, Ordering::Relaxed);
    }
    debug!(
        "private conversation stays classical: {}",
        reason::word(why).unwrap_or("")
    );
}

/// A confirmation record whose body is this one byte tells the peer that this
/// side could not finish the exchange, so it does not wait for a tag.
const ABORT_BODY: [u8; 1] = [0];

fn mark_failed(p: &mut Peer, env: &Env, why: u8) {
    fail_with(
        p,
        env,
        why,
        matches!(why, reason::CONFIRM_MISMATCH | reason::EXCHANGE_FAILED),
    );
}

/// The exchange failed. `tell`: also send the peer the abort record (not when
/// the peer told us, and not for a timeout, where it may not be reachable).
fn fail_with(p: &mut Peer, env: &Env, why: u8, tell: bool) {
    p.wipe_exchange();
    p.phase = Phase::Failed;
    p.reason = why;
    p.decided_ms = env.now;
    p.dirty = true;
    if tell {
        p.outq.push_back(Outgoing::new(KIND_CONFIRM, &ABORT_BODY));
    }
    FAILED.fetch_add(1, Ordering::Relaxed);
    debug!(
        "hybrid exchange failed: {}",
        reason::word(why).unwrap_or("")
    );
}

/// Both offers are known (or the wait is over): agree on a level once. The
/// result is counted in the process-wide capability counters and the downgrade
/// report is read here.
fn conclude(p: &mut Peer, env: &Env, forced: Option<u8>) {
    if let Some(why) = forced {
        // The peer answered the offer with "bad request": an older build. The
        // missing offer is negotiated (and counted) like any other.
        let local = Capabilities::decode(&p.our_offer).unwrap_or_else(|_| Capabilities::current());
        let req = Requirements::default();
        if let Ok(n) = negotiate_offer(&local, None, &req) {
            debug!("capability: {}", n.report.summary());
        }
        mark_classical(p, env, why);
        return;
    }
    let local = Capabilities::decode(&p.our_offer).unwrap_or_else(|_| Capabilities::current());
    let req = Requirements {
        suites: if env.mode == PqcMode::Require {
            SUITE_HYBRID_X25519_MLKEM768
        } else {
            0
        },
        features: 0,
    };
    let wire = if p.peer_offer.is_empty() {
        None
    } else {
        Some(p.peer_offer.as_slice())
    };
    match negotiate_offer(&local, wire, &req) {
        Ok(n) => {
            let usable = n.agreed.has_suite(SUITE_HYBRID_X25519_MLKEM768)
                && n.agreed.has_feature(FEATURE_FRAGMENTATION);
            if n.report.is_downgrade() {
                debug!("capability: {}", n.report.summary());
            }
            if usable {
                p.phase = Phase::Kex;
                p.waiting_since_ms = 0;
                p.dirty = true;
            } else {
                mark_classical(p, env, reason::PEER_NO_HYBRID);
            }
        }
        Err(_) => mark_classical(p, env, reason::PEER_NO_HYBRID),
    }
}

fn start_flight(p: &mut Peer, env: &Env) -> Result<(), ()> {
    let cfg = kex_config(p, env).ok_or(())?;
    let (init, msg1) = Initiator::start(cfg, &mut OsRng).map_err(|_| ())?;
    p.handshake_id = rand::random();
    let frames = fragment_message(p.handshake_id, init.suite_id(), &msg1, FRAGMENT_PAYLOAD)
        .map_err(|_| ())?;
    p.outq.clear();
    for f in frames {
        p.outq.push_back(Outgoing::new(KIND_INIT, &f));
    }
    p.initiator = Some(init);
    p.reasm = None;
    p.waiting_since_ms = 0;
    p.dirty = true;
    Ok(())
}

fn install_key(p: &mut Peer, est: &Established) {
    p.key = Some(Key(*est.session_key()));
    p.own_tag = est.confirmation();
    p.peer_tag = est.expected_peer_confirmation();
    p.peer_confirmed = false;
    p.own_confirm_sent = false;
    p.dirty = true;
}

fn ensure_confirm(p: &mut Peer, env: &Env) {
    if p.key.is_some()
        && !p.own_confirm_sent
        && (env.we_initiate() || p.peer_confirmed)
        && !p.outq.iter().any(|o| o.kind() == KIND_CONFIRM)
        && p.outq.len() < MAX_OUTQ
    {
        p.outq.push_back(Outgoing::new(KIND_CONFIRM, &p.own_tag));
    }
}

fn retry_decided(p: &mut Peer, env: &Env) {
    let after = match p.phase {
        Phase::Classical => RETRY_CLASSICAL_MS,
        Phase::Failed => RETRY_FAILED_MS,
        _ => return,
    };
    if env.now.saturating_sub(p.decided_ms) >= after {
        let sid = p.sid;
        *p = Peer::fresh(sid);
        p.dirty = true;
    }
}

fn gate_of_decided(p: &Peer, env: &Env) -> Pass {
    if env.mode != PqcMode::Require {
        return Pass::Proceed;
    }
    match p.phase {
        Phase::Failed => Pass::Refuse(FAIL_EXCHANGE),
        _ => Pass::Refuse(FAIL_NO_HYBRID),
    }
}

fn hold_or_proceed(env: &Env) -> Pass {
    if env.mode == PqcMode::Require {
        Pass::Hold
    } else {
        Pass::Proceed
    }
}

/// One decision for a contact: what to send, or whether messages may go.
fn decide(p: &mut Peer, env: &Env) -> Pass {
    for _ in 0..6 {
        retry_decided(p, env);
        ensure_confirm(p, env);
        if let Some(front) = p.outq.front() {
            return Pass::Send(front.clone());
        }
        if p.offered_ms == 0 {
            return Pass::Send(Outgoing::new(KIND_OFFER, &p.our_offer));
        }
        match p.phase {
            Phase::New => {
                p.phase = Phase::Offered;
                p.dirty = true;
            }
            Phase::Offered => {
                if !p.peer_offer.is_empty() || env.now.saturating_sub(p.offered_ms) >= OFFER_WAIT_MS
                {
                    conclude(p, env, None);
                    continue;
                }
                return hold_or_proceed(env);
            }
            Phase::Classical | Phase::Failed => return gate_of_decided(p, env),
            Phase::Kex => {
                let waited_out = p.waiting_since_ms != 0
                    && env.now.saturating_sub(p.waiting_since_ms) >= EXCHANGE_TIMEOUT_MS;
                if env.we_initiate() {
                    if p.key.is_none() && p.initiator.is_none() {
                        if start_flight(p, env).is_err() {
                            mark_failed(p, env, reason::EXCHANGE_FAILED);
                        }
                        continue;
                    }
                    // Only an exchange that produced no key is started again;
                    // once the key exists the peer may already use it, so it
                    // is kept and the peer's tag is awaited.
                    if waited_out && p.key.is_none() {
                        p.tries += 1;
                        if p.tries >= MAX_EXCHANGE_TRIES {
                            mark_failed(p, env, reason::TIMEOUT);
                        } else {
                            p.wipe_exchange();
                            p.dirty = true;
                        }
                        continue;
                    }
                }
                return hold_or_proceed(env);
            }
            Phase::Active => return Pass::Proceed,
        }
    }
    hold_or_proceed(env)
}

/// True when a delivery loop has something to do for this contact.
fn wants_send(p: &Peer, env: &Env) -> bool {
    !p.outq.is_empty()
        || p.offered_ms == 0
        || (p.phase == Phase::Offered && !p.peer_offer.is_empty())
        || (p.key.is_some() && !p.own_confirm_sent && (env.we_initiate() || p.peer_confirmed))
        || (p.phase == Phase::Kex && env.we_initiate() && p.key.is_none())
}

// ─── The shared state ───────────────────────────────────────────────────────

struct Inner {
    peers: HashMap<[u8; 32], Peer>,
    order: VecDeque<[u8; 32]>,
    guard: ReplayGuard,
}

/// The hybrid-upgrade state of all contacts of one chat store.
pub struct PqState {
    dir: PathBuf,
    keys: Arc<StateKeys>,
    own_id: [u8; 32],
    mode: AtomicU8,
    inner: Mutex<Inner>,
}

fn mode_to_u8(m: PqcMode) -> u8 {
    match m {
        PqcMode::Off => 0,
        PqcMode::Prefer => 1,
        PqcMode::Require => 2,
    }
}

impl PqState {
    pub fn new(dir: &std::path::Path, keys: Arc<StateKeys>, own_id: [u8; 32]) -> Self {
        Self {
            dir: dir.to_path_buf(),
            keys,
            own_id,
            mode: AtomicU8::new(0),
            inner: Mutex::new(Inner {
                peers: HashMap::new(),
                order: VecDeque::new(),
                guard: ReplayGuard::new(REPLAY_CAPACITY),
            }),
        }
    }

    pub fn set_mode(&self, m: PqcMode) {
        self.mode.store(mode_to_u8(m), Ordering::Relaxed);
    }

    pub fn mode(&self) -> PqcMode {
        match self.mode.load(Ordering::Relaxed) {
            1 => PqcMode::Prefer,
            2 => PqcMode::Require,
            _ => PqcMode::Off,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn path(&self, peer: &[u8; 32]) -> PathBuf {
        crate::paths::chat_pq_file(&self.dir, &file_stem(&self.own_id, peer))
    }

    fn env(&self, peer: &[u8; 32], now: u64) -> Env {
        Env {
            own: self.own_id,
            peer: *peer,
            mode: self.mode(),
            now,
        }
    }

    fn load(&self, peer: &[u8; 32]) -> Option<Peer> {
        let path = self.path(peer);
        if !path.exists() {
            return None;
        }
        match doc::read_document(&self.keys, Label::ChatSessions, &path) {
            Ok(bytes) => {
                if let Some(p) = Peer::from_bytes(&bytes) {
                    return Some(p);
                }
                warn!("a hybrid-upgrade document is damaged; it was set aside");
            }
            Err(e) => warn!("a hybrid-upgrade document cannot be read ({e}); it was set aside"),
        }
        let _ = state_crypto::set_aside(&path);
        None
    }

    fn save(&self, peer: &[u8; 32], p: &Peer) -> Result<(), ()> {
        let bytes = p.to_bytes();
        doc::write_document(&self.keys, Label::ChatSessions, &self.path(peer), &bytes).map_err(
            |e| {
                warn!("a hybrid-upgrade document cannot be written: {e}");
            },
        )
    }

    fn remove_file(&self, peer: &[u8; 32]) {
        let _ = state_crypto::overwrite_and_remove(&self.path(peer));
    }

    /// The record of `peer` for session `sid`: from memory, from disk, or new.
    /// A record that belongs to another session is dropped (its key is wiped).
    fn slot<'a>(&self, g: &'a mut Inner, peer: &[u8; 32], sid: [u8; 32]) -> &'a mut Peer {
        let Inner { peers, order, .. } = g;
        self.slot_split(peers, order, peer, sid)
    }

    /// Write the record if a decision changed it.
    fn persist(&self, peer: &[u8; 32], p: &mut Peer) -> Result<(), ()> {
        if !p.dirty {
            return Ok(());
        }
        // The document holds the session key, so it is written only with
        // something worth keeping; a record that never left `New` is not.
        if p.phase == Phase::New && p.key.is_none() && p.peer_offer.is_empty() {
            p.dirty = false;
            return Ok(());
        }
        self.save(peer, p)?;
        p.dirty = false;
        Ok(())
    }

    // ── Message keys ─────────────────────────────────────────────────────────

    /// The hybrid key to seal a message with: only when both sides finished.
    pub fn seal_key(&self, peer: &[u8; 32], sid: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
        self.key_of(peer, sid, |p| p.phase == Phase::Active)
    }

    /// The hybrid key to try when opening a message: any derived key, because
    /// the sender may already use it once it verified our tag.
    pub fn open_key(&self, peer: &[u8; 32], sid: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
        self.key_of(peer, sid, |p| matches!(p.phase, Phase::Kex | Phase::Active))
    }

    /// A key lookup creates no state: a contact that never took part in the
    /// upgrade has no record and no file, and stays that way.
    fn key_of(
        &self,
        peer: &[u8; 32],
        sid: &[u8; 32],
        usable: impl Fn(&Peer) -> bool,
    ) -> Option<Zeroizing<[u8; 32]>> {
        let mut g = self.lock();
        if !g.peers.contains_key(peer) {
            if !self.path(peer).exists() {
                return None;
            }
            // A document exists: bring it into memory (it is checked below).
            let Inner { peers, order, .. } = &mut *g;
            let _ = self.slot_split(peers, order, peer, *sid);
        }
        let p = g.peers.get(peer)?;
        if p.sid != *sid || !usable(p) {
            return None;
        }
        p.key.as_ref().map(|k| Zeroizing::new(k.0))
    }

    // ── The delivery loop ────────────────────────────────────────────────────

    /// What to do next for `peer`. `sid` is the session ID, or `None` before
    /// any session exists. With `have_text` false a hold or refusal is not
    /// needed (nothing waits), so it is reported as `Proceed`.
    pub fn pass(&self, peer: &[u8; 32], sid: Option<[u8; 32]>, have_text: bool, now: u64) -> Pass {
        let mode = self.mode();
        if mode == PqcMode::Off {
            return Pass::Proceed;
        }
        let Some(sid) = sid else {
            // No session yet: the offer opens it (nothing is held back).
            return Pass::Send(Outgoing::new(KIND_OFFER, &Capabilities::current().encode()));
        };
        let env = self.env(peer, now);
        let mut g = self.lock();
        let p = self.slot(&mut g, peer, sid);
        let out = decide(p, &env);
        let _ = self.persist(peer, p);
        match out {
            Pass::Hold | Pass::Refuse(_) if !have_text => Pass::Proceed,
            other => other,
        }
    }

    /// True when the delivery loop for `peer` has a hybrid-upgrade step to do
    /// (used to wake it after a record arrived).
    pub fn wants_attention(&self, peer: &[u8; 32], now: u64) -> bool {
        let mode = self.mode();
        if mode == PqcMode::Off {
            return false;
        }
        let env = self.env(peer, now);
        let g = self.lock();
        match g.peers.get(peer) {
            Some(p) => wants_send(p, &env),
            // Nothing is known about this contact yet: offer.
            None => true,
        }
    }

    /// Milliseconds until a decision for `peer` falls due without anything
    /// arriving: the wait for the peer's offer ends. `None` when no time-driven
    /// step is pending. The delivery loop waits that long instead of leaving,
    /// so "classical only" is decided and shown without a further message.
    pub fn deadline(&self, peer: &[u8; 32], now: u64) -> Option<u64> {
        if self.mode() == PqcMode::Off {
            return None;
        }
        let g = self.lock();
        let p = g.peers.get(peer)?;
        if p.phase == Phase::Offered && p.peer_offer.is_empty() && p.offered_ms > 0 {
            let due = p.offered_ms.saturating_add(OFFER_WAIT_MS);
            return Some(due.saturating_sub(now).max(1));
        }
        None
    }

    /// Report how the delivery of `out` ended.
    pub fn sent(
        &self,
        peer: &[u8; 32],
        sid: &[u8; 32],
        out: &Outgoing,
        outcome: SendOutcome,
        now: u64,
    ) {
        let env = self.env(peer, now);
        let mut g = self.lock();
        let p = self.slot(&mut g, peer, *sid);
        match (outcome, out.kind()) {
            (SendOutcome::Delivered, KIND_OFFER) => {
                if p.offered_ms == 0 {
                    p.offered_ms = now.max(1);
                    OFFERS_SENT.fetch_add(1, Ordering::Relaxed);
                }
                if p.phase == Phase::New {
                    p.phase = Phase::Offered;
                }
                p.dirty = true;
            }
            (SendOutcome::Delivered, kind) => {
                if p.outq.front() == Some(out) {
                    p.outq.pop_front();
                }
                if kind == KIND_CONFIRM {
                    p.own_confirm_sent = true;
                }
                if p.outq.is_empty() && p.phase == Phase::Kex {
                    p.waiting_since_ms = now.max(1);
                }
                p.dirty = true;
            }
            (SendOutcome::NotUnderstood, KIND_OFFER) => {
                if p.offered_ms == 0 {
                    p.offered_ms = now.max(1);
                }
                if !matches!(p.phase, Phase::Classical | Phase::Active) {
                    conclude(p, &env, Some(reason::PEER_OLD_BUILD));
                }
                p.dirty = true;
            }
            (SendOutcome::NotUnderstood, _) => {
                // The peer does not take this record. An abort that is not
                // understood is simply dropped, so nothing loops.
                if p.outq.front() == Some(out) {
                    p.outq.pop_front();
                }
                if matches!(p.phase, Phase::New | Phase::Offered | Phase::Kex) {
                    fail_with(p, &env, reason::EXCHANGE_FAILED, false);
                }
            }
        }
        let _ = self.persist(peer, p);
    }

    // ── Receiving ────────────────────────────────────────────────────────────

    /// Apply a hybrid-upgrade record that opened in session `sid`. `Err` means
    /// the effect could not be written down: the sender should try again.
    pub fn on_record(
        &self,
        peer: &[u8; 32],
        sid: &[u8; 32],
        plain: &[u8],
        now: u64,
    ) -> Result<(), ()> {
        let mode = self.mode();
        let Some((&kind, body)) = plain.split_first() else {
            return Ok(());
        };
        if mode == PqcMode::Off || !is_pq_kind(kind) {
            return Ok(());
        }
        let env = self.env(peer, now);
        let mut g = self.lock();
        let Inner {
            peers,
            order,
            guard,
        } = &mut *g;
        let p = self.slot_split(peers, order, peer, *sid);
        match kind {
            KIND_OFFER => on_offer(p, body),
            KIND_INIT => on_init(p, &env, guard, body),
            KIND_RESP => on_resp(p, &env, body),
            KIND_CONFIRM => on_confirm(p, &env, body),
            _ => {}
        }
        self.persist(peer, p)
    }

    /// `slot` for callers that hold the parts of `Inner` separately.
    fn slot_split<'a>(
        &self,
        peers: &'a mut HashMap<[u8; 32], Peer>,
        order: &mut VecDeque<[u8; 32]>,
        peer: &[u8; 32],
        sid: [u8; 32],
    ) -> &'a mut Peer {
        let stale = peers.get(peer).is_some_and(|p| p.sid != sid);
        if stale {
            peers.remove(peer);
            order.retain(|x| x != peer);
            self.remove_file(peer);
        }
        if !peers.contains_key(peer) {
            if peers.len() >= MAX_PEERS {
                if let Some(old) = order.pop_front() {
                    peers.remove(&old);
                }
            }
            let p = match self.load(peer) {
                Some(p) if p.sid == sid => p,
                Some(_) => {
                    self.remove_file(peer);
                    Peer::fresh(sid)
                }
                None => Peer::fresh(sid),
            };
            peers.insert(*peer, p);
            order.push_back(*peer);
        }
        peers.get_mut(peer).expect("just inserted")
    }

    // ── Showing it ───────────────────────────────────────────────────────────

    /// What to show for a contact.
    pub fn view(&self, peer: &[u8; 32]) -> PqView {
        let mode = self.mode();
        let mut g = self.lock();
        if !g.peers.contains_key(peer) {
            if let Some(p) = self.load(peer) {
                if g.peers.len() >= MAX_PEERS {
                    if let Some(old) = g.order.pop_front() {
                        g.peers.remove(&old);
                    }
                }
                g.peers.insert(*peer, p);
                g.order.push_back(*peer);
            }
        }
        match g.peers.get(peer) {
            Some(p) => match p.phase {
                Phase::Active => PqView {
                    state: "hybrid",
                    reason: None,
                },
                Phase::Classical => PqView {
                    state: "classical",
                    reason: reason::word(p.reason),
                },
                Phase::Failed => PqView {
                    state: "failed",
                    reason: reason::word(p.reason),
                },
                Phase::New | Phase::Offered | Phase::Kex => PqView {
                    state: if mode == PqcMode::Off {
                        "off"
                    } else {
                        "pending"
                    },
                    reason: None,
                },
            },
            None => PqView {
                state: if mode == PqcMode::Off {
                    "off"
                } else {
                    "pending"
                },
                reason: None,
            },
        }
    }

    /// Forget a contact (the conversation was deleted or the session reset).
    pub fn forget(&self, peer: &[u8; 32]) {
        let mut g = self.lock();
        g.peers.remove(peer);
        g.order.retain(|x| x != peer);
        drop(g);
        self.remove_file(peer);
    }

    /// Drop every key from memory (the service stops). Documents stay.
    pub fn clear_memory(&self) {
        let mut g = self.lock();
        g.peers.clear();
        g.order.clear();
    }

    /// Wipe: drop every key from memory and overwrite and remove the documents.
    pub fn wipe(&self) {
        let peers: Vec<[u8; 32]> = {
            let mut g = self.lock();
            let v = g.peers.keys().copied().collect();
            g.peers.clear();
            g.order.clear();
            v
        };
        for p in peers {
            self.remove_file(&p);
        }
        if let Ok(rd) = std::fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                let path = e.path();
                if path.extension().is_some_and(|x| x == "pq") {
                    let _ = state_crypto::overwrite_and_remove(&path);
                }
            }
        }
    }

    /// Contacts held in memory (tests and diagnostics).
    pub fn in_memory(&self) -> usize {
        self.lock().peers.len()
    }
}

// ─── Record handlers ────────────────────────────────────────────────────────

fn on_offer(p: &mut Peer, body: &[u8]) {
    if body.is_empty() || body.len() > MAX_OFFER_BYTES {
        return;
    }
    if p.peer_offer.is_empty() {
        OFFERS_RECEIVED.fetch_add(1, Ordering::Relaxed);
    }
    if p.peer_offer == body {
        return;
    }
    // A late offer re-opens a decision taken for want of one.
    if p.phase == Phase::Classical && p.reason == reason::PEER_NO_HYBRID {
        p.phase = Phase::Offered;
        p.reason = reason::NONE;
    }
    if matches!(p.phase, Phase::New | Phase::Offered | Phase::Classical) {
        p.peer_offer = body.to_vec();
        p.dirty = true;
    }
}

fn on_init(p: &mut Peer, env: &Env, guard: &mut ReplayGuard, body: &[u8]) {
    if env.we_initiate() || p.peer_offer.is_empty() {
        return;
    }
    if matches!(p.phase, Phase::New | Phase::Offered) {
        conclude(p, env, None);
    }
    if p.phase != Phase::Kex || p.peer_confirmed {
        return;
    }
    let reasm = p.reasm.get_or_insert_with(MessageReassembler::new);
    reasm.expire(env.now);
    let asm = match reasm.push_frame(body, env.now) {
        Ok(Some(a)) => a,
        Ok(None) => return,
        Err(_) => {
            // A damaged fragment: the partial message is dropped.
            p.reasm = None;
            return;
        }
    };
    p.reasm = None;
    if asm.suite_id != SUITE_ID_HYBRID {
        return;
    }
    let Some(cfg) = kex_config(p, env) else {
        mark_failed(p, env, reason::EXCHANGE_FAILED);
        return;
    };
    match Responder::accept(cfg, &asm.data, guard, &mut OsRng) {
        Ok((est, msg2)) => {
            install_key(p, &est);
            p.outq.clear();
            match fragment_message(asm.handshake_id, SUITE_ID_HYBRID, &msg2, FRAGMENT_PAYLOAD) {
                Ok(frames) => {
                    for f in frames {
                        p.outq.push_back(Outgoing::new(KIND_RESP, &f));
                    }
                }
                Err(_) => mark_failed(p, env, reason::EXCHANGE_FAILED),
            }
        }
        // The same first message again (a retry): nothing to do.
        Err(HybridError::Replay) => {}
        Err(_) => mark_failed(p, env, reason::EXCHANGE_FAILED),
    }
}

fn on_resp(p: &mut Peer, env: &Env, body: &[u8]) {
    if !env.we_initiate() || p.phase != Phase::Kex || p.initiator.is_none() {
        return;
    }
    let reasm = p.reasm.get_or_insert_with(MessageReassembler::new);
    reasm.expire(env.now);
    let asm = match reasm.push_frame(body, env.now) {
        Ok(Some(a)) => a,
        Ok(None) => return,
        Err(_) => {
            p.reasm = None;
            return;
        }
    };
    p.reasm = None;
    if asm.handshake_id != p.handshake_id {
        return;
    }
    let Some(init) = p.initiator.take() else {
        return;
    };
    if asm.suite_id != init.suite_id() {
        mark_failed(p, env, reason::EXCHANGE_FAILED);
        return;
    }
    match init.finish(&asm.data) {
        Ok(est) => {
            install_key(p, &est);
            p.waiting_since_ms = 0;
        }
        Err(_) => mark_failed(p, env, reason::EXCHANGE_FAILED),
    }
}

fn on_confirm(p: &mut Peer, env: &Env, body: &[u8]) {
    if body == ABORT_BODY {
        // The peer could not finish the exchange. It never uses a key it
        // failed to confirm, so ours can go.
        if p.phase == Phase::Kex {
            fail_with(p, env, reason::EXCHANGE_FAILED, false);
        }
        return;
    }
    if body.len() != 32 || p.key.is_none() || p.peer_confirmed {
        return;
    }
    if bool::from(p.peer_tag.ct_eq(body)) {
        p.peer_confirmed = true;
        p.dirty = true;
        if p.phase == Phase::Kex {
            p.phase = Phase::Active;
            p.decided_ms = env.now;
            HYBRID_SESSIONS.fetch_add(1, Ordering::Relaxed);
        }
    } else {
        // The two sides did not derive the same key: the transcripts differ
        // (an altered message or offer).
        mark_failed(p, env, reason::CONFIRM_MISMATCH);
    }
}

#[cfg(test)]
pub(crate) fn key_drops() -> usize {
    KEY_DROPS.with(|c| c.get())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Peer {
        let mut p = Peer::fresh(rand::random());
        p.phase = Phase::Active;
        p.reason = reason::NONE;
        p.decided_ms = 7;
        p.offered_ms = 5;
        p.peer_offer = Capabilities::current().encode();
        p.key = Some(Key(rand::random()));
        p.own_tag = rand::random();
        p.peer_tag = rand::random();
        p.peer_confirmed = true;
        p.own_confirm_sent = true;
        p
    }

    #[test]
    fn the_document_round_trips_and_rejects_every_truncation() {
        let p = sample();
        let bytes = p.to_bytes();
        let back = Peer::from_bytes(&bytes).expect("reads back");
        assert_eq!(back.sid, p.sid);
        assert_eq!(back.phase, Phase::Active);
        assert_eq!(back.peer_offer, p.peer_offer);
        assert_eq!(back.key.as_ref().unwrap().0, p.key.as_ref().unwrap().0);
        assert_eq!(back.own_tag, p.own_tag);
        assert_eq!(back.peer_tag, p.peer_tag);
        assert!(back.peer_confirmed && back.own_confirm_sent);
        for n in 0..bytes.len() {
            assert!(Peer::from_bytes(&bytes[..n]).is_none(), "prefix {n}");
        }
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert!(Peer::from_bytes(&longer).is_none());
        let mut bad_phase = bytes.to_vec();
        bad_phase[1 + 32] = 3;
        assert!(Peer::from_bytes(&bad_phase).is_none());
    }

    #[test]
    fn a_document_without_a_key_has_none() {
        let mut p = sample();
        p.key = None;
        p.peer_confirmed = false;
        p.own_confirm_sent = false;
        let back = Peer::from_bytes(&p.to_bytes()).unwrap();
        assert!(back.key.is_none());
    }

    #[test]
    fn an_offer_longer_than_the_cap_is_not_stored() {
        let mut p = Peer::fresh(rand::random());
        on_offer(&mut p, &vec![0u8; MAX_OFFER_BYTES + 1]);
        assert!(p.peer_offer.is_empty());
        on_offer(&mut p, &Capabilities::current().encode());
        assert!(!p.peer_offer.is_empty());
    }

    #[test]
    fn dropping_a_peer_zeroizes_its_key() {
        let before = key_drops();
        let p = sample();
        drop(p);
        assert_eq!(key_drops(), before + 1);
    }

    #[test]
    fn the_record_kinds_do_not_overlap_the_other_chat_kinds() {
        for k in [KIND_OFFER, KIND_INIT, KIND_RESP, KIND_CONFIRM] {
            assert!(is_pq_kind(k));
            assert!(!matches!(k, 0 | 1 | 2 | 0x10..=0x12));
        }
        assert!(!is_pq_kind(0x24) && !is_pq_kind(0x1f));
    }
}
