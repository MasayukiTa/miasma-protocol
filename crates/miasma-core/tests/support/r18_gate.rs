//! Shared pieces of the r18 adversarial / chaos / compatibility gate.
//! Include with `#[path = "support/r18_gate.rs"] mod gate;`.
//!
//! * a seeded schedule (`seeds`, `rng`) so that every run is reproducible and a
//!   failure names the seed that caused it;
//! * a message-level hostile channel (loss, duplication, reordering,
//!   truncation, bit flips);
//! * a per-thread allocation meter, to show that memory stays bounded;
//! * a world of dissolved segments plus a piece source whose transports,
//!   holders and clock are scripted;
//! * a maintenance backend with durable "disk" state and a crash that can be
//!   injected at the Nth backend call.
//!
//! Nothing here binds a port or touches a path outside a caller-owned directory.

#![allow(dead_code)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use miasma_core::{
    dissolution::segment::dissolve_segment_with,
    network::types::{DhtRecord, ShardLocation},
    network::AnonymityPolicy,
    repair::{
        holder_id_of, Candidate, EvidenceConfig, MaintenanceBackend, MaintenanceConfig,
        PieceMaintenanceConfig, ProbeOutcome, ProbeResult,
    },
    transfer::{
        PasswordProtection, PieceSource, Protection, RetryConfig, SegmentEntry, SegmentSink,
        SinkError, StreamSpec, TransferManifest,
    },
    ContentId, DissolutionParams, MiasmaError, MiasmaShare, PayloadTransport,
    PayloadTransportError, PayloadTransportKind, PayloadTransportSelector, PolicyFetchError,
    TransportPhase,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use zeroize::Zeroizing;

// ─── Seeds ───────────────────────────────────────────────────────────────────

/// The seeds one scenario runs. `R18_GATE_SEEDS=7` runs exactly seed 7 (to
/// reproduce a failure); `R18_GATE_SEEDS=0..200` runs a range; the default is
/// `0..default_count`.
pub fn seeds(default_count: u64) -> Vec<u64> {
    if let Ok(v) = std::env::var("R18_GATE_SEEDS") {
        if let Some((a, b)) = v.split_once("..") {
            if let (Ok(a), Ok(b)) = (a.trim().parse::<u64>(), b.trim().parse::<u64>()) {
                return (a..b).collect();
            }
        }
        let list: Vec<u64> = v
            .split(',')
            .filter_map(|s| s.trim().parse::<u64>().ok())
            .collect();
        if !list.is_empty() {
            return list;
        }
    }
    (0..default_count).collect()
}

/// A reproducible random stream for `(seed, purpose)`.
pub fn rng(seed: u64, purpose: u64) -> StdRng {
    StdRng::seed_from_u64(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ purpose)
}

// ─── Per-thread allocation meter ─────────────────────────────────────────────

thread_local! {
    static LIVE: Cell<i64> = const { Cell::new(0) };
    static PEAK: Cell<i64> = const { Cell::new(0) };
}

/// Counts the bytes each thread has allocated and not yet freed. Install it as
/// the global allocator of a test binary with
/// `#[global_allocator] static A: gate::Meter = gate::Meter;`.
pub struct Meter;

unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            bump(layout.size() as i64);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        bump(-(layout.size() as i64));
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(layout);
        if !p.is_null() {
            bump(layout.size() as i64);
        }
        p
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, layout, new_size);
        if !p.is_null() {
            bump(new_size as i64 - layout.size() as i64);
        }
        p
    }
}

fn bump(delta: i64) {
    let _ = LIVE.try_with(|live| {
        let now = live.get() + delta;
        live.set(now);
        let _ = PEAK.try_with(|peak| {
            if now > peak.get() {
                peak.set(now);
            }
        });
    });
}

/// Highest number of bytes this thread held above its starting point while
/// `f` ran. Valid for synchronous code on the calling thread.
pub fn peak_heap_growth<T>(f: impl FnOnce() -> T) -> (T, i64) {
    let base = LIVE.with(|l| l.get());
    PEAK.with(|p| p.set(base));
    let out = f();
    let peak = PEAK.with(|p| p.get());
    (out, peak - base)
}

// ─── Hostile channel ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default)]
pub struct Hostility {
    pub loss_pct: u32,
    pub dup_pct: u32,
    pub reorder: bool,
    pub truncate_pct: u32,
    pub flip_pct: u32,
}

impl Hostility {
    /// Delivery faults only: nothing is altered, so nothing may be mis-assembled.
    pub fn delivery_only() -> Self {
        Self {
            loss_pct: 25,
            dup_pct: 30,
            reorder: true,
            truncate_pct: 0,
            flip_pct: 0,
        }
    }
    /// Delivery faults and damage to the bytes.
    pub fn damaging() -> Self {
        Self {
            loss_pct: 15,
            dup_pct: 25,
            reorder: true,
            truncate_pct: 20,
            flip_pct: 20,
        }
    }
}

/// What a bad network does to a batch of frames.
pub fn hostile(frames: Vec<Vec<u8>>, h: Hostility, rng: &mut StdRng) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for mut f in frames {
        if rng.gen_range(0..100) < h.loss_pct {
            continue;
        }
        if !f.is_empty() && rng.gen_range(0..100) < h.truncate_pct {
            let cut = rng.gen_range(0..f.len());
            f.truncate(cut);
        }
        if !f.is_empty() && rng.gen_range(0..100) < h.flip_pct {
            let i = rng.gen_range(0..f.len());
            f[i] ^= 1 << rng.gen_range(0..8);
        }
        if rng.gen_range(0..100) < h.dup_pct {
            out.push(f.clone());
        }
        out.push(f);
    }
    if h.reorder {
        for i in (1..out.len()).rev() {
            let j = rng.gen_range(0..=i);
            out.swap(i, j);
        }
    }
    out
}

// ─── Files ───────────────────────────────────────────────────────────────────

pub fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(files_under(&p));
            } else {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Files below `dir` that look like a half-finished write or a temp file.
pub fn temp_like_files(dir: &Path) -> Vec<PathBuf> {
    files_under(dir)
        .into_iter()
        .filter(|p| {
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            let ext = p
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            matches!(ext.as_str(), "part" | "tmp" | "new" | "partial")
                || name.starts_with(".tmp")
                || name.ends_with('~')
        })
        .collect()
}

/// Files below `dir` that contain `needle` verbatim.
pub fn files_containing(dir: &Path, needle: &[u8]) -> Vec<PathBuf> {
    files_under(dir)
        .into_iter()
        .filter(|p| {
            std::fs::read(p)
                .map(|b| b.windows(needle.len()).any(|w| w == needle))
                .unwrap_or(false)
        })
        .collect()
}

/// Names of `.part` files in the process temp directory (the receive engine
/// must leave none behind).
pub fn part_files_in_temp() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(std::env::temp_dir())
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".part"))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

// ─── A world of dissolved segments ───────────────────────────────────────────

pub const SEG: usize = 1024;
pub const MARK: &[u8] = b"R18-GATE-PLAINTEXT-MARKER:";

/// Plaintext in which a marker recurs, so any leak into a file, an error text
/// or a log line is easy to see.
pub fn content(len: usize, rng: &mut StdRng) -> Vec<u8> {
    let salt: u8 = rng.gen();
    (0..len)
        .map(|i| {
            if i % 64 < MARK.len() {
                MARK[i % 64]
            } else {
                (i as u8).wrapping_mul(31).wrapping_add(salt)
            }
        })
        .collect()
}

pub struct World {
    pub data: Vec<u8>,
    pub mid: ContentId,
    pub record: DhtRecord,
    pub manifest: TransferManifest,
    pub shares: HashMap<(u32, u16), MiasmaShare>,
    pub password: Option<String>,
    pub k: usize,
    pub n: usize,
}

/// `segments` segments of `SEG` bytes dissolved with `k` of `n`; slot `s` of
/// every segment is held by the "holder" whose index is `s`.
pub fn build_world(
    segments: usize,
    k: usize,
    n: usize,
    protected: bool,
    rng: &mut StdRng,
) -> World {
    let data = content(segments * SEG, rng);
    let params = DissolutionParams {
        data_shards: k,
        total_shards: n,
    };
    let mid = ContentId::compute(&data, &params.to_param_bytes());
    let password = protected.then(|| format!("pw-1{:032x}", rng.gen::<u128>()));
    let (protection, key) = match &password {
        Some(pw) => {
            let (p, key) = PasswordProtection::create_with_cost(pw, 64, 1, 1).unwrap();
            (Protection::Password(p), Some(key))
        }
        None => (Protection::None, None),
    };
    let mut manifest = TransferManifest::new(
        &mid,
        [0x5a; 32],
        params,
        SEG as u32,
        data.len() as u64,
        protection,
    );
    let mut shares = HashMap::new();
    let mut locations = Vec::new();
    for (i, chunk) in data.chunks(SEG).enumerate() {
        let (_, seg_shares) =
            dissolve_segment_with(chunk, &mid, i as u32, 0, params, key.as_ref()).unwrap();
        manifest
            .push_segment(SegmentEntry::from_dissolved(i as u32, &mid, chunk, &seg_shares).unwrap())
            .unwrap();
        for s in seg_shares {
            locations.push(ShardLocation {
                peer_id_bytes: vec![s.slot_index as u8],
                shard_index: s.slot_index,
                segment_index: i as u32,
                addrs: vec![],
            });
            shares.insert((i as u32, s.slot_index), s);
        }
    }
    let record = DhtRecord {
        mid_digest: *mid.as_bytes(),
        data_shards: k as u8,
        total_shards: n as u8,
        version: 1,
        locations,
        published_at: 1,
    };
    World {
        data,
        mid,
        record,
        manifest,
        shares,
        password,
        k,
        n,
    }
}

pub fn quick_retry() -> RetryConfig {
    RetryConfig {
        max_attempts_per_segment: 3,
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(2),
    }
}

pub fn stream_spec(w: &World) -> StreamSpec {
    let mut s = StreamSpec::new(w.mid.clone(), w.record.clone(), Some(w.manifest.clone()));
    s.password = w.password.as_ref().map(|p| Zeroizing::new(p.clone()));
    s.retry = quick_retry();
    s
}

// ─── The consumer ────────────────────────────────────────────────────────────

/// A consumer that keeps what it is given in a wiping buffer, can be slow, and
/// notes how it was ended.
pub struct VaultSink {
    pub collected: Zeroizing<Vec<u8>>,
    /// The indices of the segments it was given, in order.
    pub seen: Vec<u32>,
    pub delay: Duration,
    pub completed: Option<u64>,
    pub aborted: u32,
    pub completes: u32,
}

impl VaultSink {
    pub fn new(delay: Duration) -> Self {
        Self {
            collected: Zeroizing::new(Vec::new()),
            seen: Vec::new(),
            delay,
            completed: None,
            aborted: 0,
            completes: 0,
        }
    }
}

#[async_trait]
impl SegmentSink for VaultSink {
    async fn accept(&mut self, index: u32, data: &[u8]) -> Result<(), SinkError> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        self.collected.extend_from_slice(data);
        self.seen.push(index);
        Ok(())
    }
    fn complete(&mut self, total_bytes: u64) {
        self.completed = Some(total_bytes);
        self.completes += 1;
    }
    fn abort(&mut self) {
        self.aborted += 1;
        self.collected.clear();
    }
}

// ─── Scripted transports and holders ─────────────────────────────────────────

/// How one holder behaves. Times are measured from the start of the script on
/// the (paused) tokio clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct HolderScript {
    /// Time one answer takes.
    pub slow: Duration,
    /// The holder is gone from this moment on.
    pub gone_after: Option<Duration>,
}

pub struct Script {
    pub started: tokio::time::Instant,
    pub holders: Mutex<HashMap<u16, HolderScript>>,
    /// Transports that are down for everybody.
    pub down: Mutex<HashSet<&'static str>>,
}

impl Script {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            started: tokio::time::Instant::now(),
            holders: Mutex::new(HashMap::new()),
            down: Mutex::new(HashSet::new()),
        })
    }
    pub fn set_holder(&self, slot: u16, h: HolderScript) {
        self.holders.lock().unwrap().insert(slot, h);
    }
    pub fn set_down(&self, kind: PayloadTransportKind, down: bool) {
        let name = kind_name(kind);
        let mut g = self.down.lock().unwrap();
        if down {
            g.insert(name);
        } else {
            g.remove(name);
        }
    }
}

fn kind_name(kind: PayloadTransportKind) -> &'static str {
    match kind {
        PayloadTransportKind::DirectLibp2p => "direct-libp2p",
        PayloadTransportKind::TcpDirect => "tcp-direct",
        PayloadTransportKind::WssTunnel => "wss-tunnel",
        PayloadTransportKind::RelayHop => "relay-hop",
        PayloadTransportKind::ObfuscatedQuic => "obfuscated-quic",
    }
}

/// One payload transport that serves the world's pieces under a script and
/// counts every attempt.
pub struct ScriptedTransport {
    kind: PayloadTransportKind,
    shares: Arc<HashMap<(u32, u16), MiasmaShare>>,
    script: Arc<Script>,
    pub attempts: Arc<AtomicUsize>,
}

impl ScriptedTransport {
    pub fn new(
        kind: PayloadTransportKind,
        shares: Arc<HashMap<(u32, u16), MiasmaShare>>,
        script: Arc<Script>,
    ) -> (Self, Arc<AtomicUsize>) {
        let attempts = Arc::new(AtomicUsize::new(0));
        (
            Self {
                kind,
                shares,
                script,
                attempts: attempts.clone(),
            },
            attempts,
        )
    }
}

#[async_trait]
impl PayloadTransport for ScriptedTransport {
    fn kind(&self) -> PayloadTransportKind {
        self.kind
    }
    async fn fetch_share(
        &self,
        peer_addr: &str,
        _mid_digest: [u8; 32],
        slot_index: u16,
        segment_index: u32,
    ) -> Result<Option<MiasmaShare>, PayloadTransportError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let refuse = |why: &str| PayloadTransportError {
            phase: TransportPhase::Session,
            message: format!("{peer_addr}: {why}"),
        };
        if self
            .script
            .down
            .lock()
            .unwrap()
            .contains(kind_name(self.kind))
        {
            return Err(refuse("transport down"));
        }
        let h = self
            .script
            .holders
            .lock()
            .unwrap()
            .get(&slot_index)
            .copied()
            .unwrap_or_default();
        if let Some(gone) = h.gone_after {
            if self.script.started.elapsed() >= gone {
                return Err(refuse("holder gone"));
            }
        }
        if !h.slow.is_zero() {
            tokio::time::sleep(h.slow).await;
            // The holder may have left while the answer was being prepared.
            if let Some(gone) = h.gone_after {
                if self.script.started.elapsed() >= gone {
                    return Err(refuse("holder gone"));
                }
            }
        }
        Ok(self.shares.get(&(segment_index, slot_index)).cloned())
    }
}

/// The receive engine's piece source backed by a transport selector under an
/// anonymity policy. A policy refusal is an error, never a quiet downgrade.
pub struct SelectorSource {
    pub selector: PayloadTransportSelector,
    pub policy: AnonymityPolicy,
}

#[async_trait]
impl PieceSource for SelectorSource {
    async fn fetch_piece(
        &self,
        mid: &ContentId,
        segment: u32,
        slot: u16,
        holder: &ShardLocation,
    ) -> Result<Option<MiasmaShare>, MiasmaError> {
        let addr = format!("holder-{}", holder.shard_index);
        match self
            .selector
            .fetch_share_with_policy(self.policy, &addr, *mid.as_bytes(), slot, segment)
            .await
        {
            Ok(t) => Ok(Some(t.share)),
            Err(PolicyFetchError::NoPermittedTransport { .. }) => Err(MiasmaError::Network(
                "the anonymity policy forbids every configured transport".into(),
            )),
            Err(PolicyFetchError::Exhausted(e)) => {
                if e.attempts.last().is_some_and(|a| a.succeeded) {
                    Ok(None)
                } else {
                    Err(MiasmaError::Network(
                        "every permitted transport failed".into(),
                    ))
                }
            }
        }
    }
}

// ─── Maintenance with durable state and an injectable crash ──────────────────

pub fn holder_name(h: &str) -> String {
    format!("raw:{}", hex::encode(h.as_bytes()))
}

pub fn make_share(mid: &[u8; 32], segment: u32, slot: u16) -> MiasmaShare {
    MiasmaShare::new(
        &ContentId::from_digest(*mid),
        segment,
        slot,
        vec![slot as u8; 100],
        vec![7; 32],
        [3u8; 12],
        100,
        1,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPhase {
    /// The process dies before the call has any effect.
    Before,
    /// The call took effect and the process dies before it learns of it.
    After,
}

pub struct DState {
    pub record: DhtRecord,
    /// Pieces each holder physically stores (also the unreachable ones).
    pub stored: BTreeMap<String, BTreeSet<(u32, u16)>>,
    pub dead: HashSet<String>,
    pub candidates: Vec<Candidate>,
    /// The publisher's own copies, which maintenance replicates from.
    pub local: BTreeSet<(u32, u16)>,
    pub calls: usize,
    pub crash: Option<(usize, CrashPhase)>,
    pub crashed: bool,
    pub pushes: Vec<(String, u32, u16)>,
    pub commits: usize,
    /// The record store refuses this many commits (a busy disk).
    pub fail_commit: usize,
    /// Every record that was ever visible (for the invariant check).
    pub history: Vec<DhtRecord>,
}

pub struct Durable {
    pub state: Mutex<DState>,
    pub crashed: tokio::sync::Notify,
}

impl Durable {
    pub fn new(record: DhtRecord, candidates: Vec<Candidate>) -> Arc<Self> {
        let mut stored: BTreeMap<String, BTreeSet<(u32, u16)>> = BTreeMap::new();
        let mut local = BTreeSet::new();
        for l in &record.locations {
            stored
                .entry(holder_id_of(l))
                .or_default()
                .insert((l.segment_index, l.shard_index));
            local.insert((l.segment_index, l.shard_index));
        }
        Arc::new(Self {
            state: Mutex::new(DState {
                history: vec![record.clone()],
                record,
                stored,
                dead: HashSet::new(),
                candidates,
                local,
                calls: 0,
                crash: None,
                crashed: false,
                pushes: Vec::new(),
                commits: 0,
                fail_commit: 0,
            }),
            crashed: tokio::sync::Notify::new(),
        })
    }

    pub fn kill(&self, holder: &str) {
        self.state.lock().unwrap().dead.insert(holder_name(holder));
    }

    pub fn record(&self) -> DhtRecord {
        self.state.lock().unwrap().record.clone()
    }

    /// Arm a crash at the `n`th backend call (1-based) from now.
    pub fn arm_crash(&self, n: usize, phase: CrashPhase) {
        let mut s = self.state.lock().unwrap();
        s.calls = 0;
        s.crashed = false;
        s.crash = Some((n, phase));
    }

    pub fn disarm(&self) {
        let mut s = self.state.lock().unwrap();
        s.crash = None;
        s.crashed = false;
    }

    pub fn calls(&self) -> usize {
        self.state.lock().unwrap().calls
    }

    /// Count a call; returns the crash phase when this call is the doomed one.
    fn enter(&self) -> Option<CrashPhase> {
        let mut s = self.state.lock().unwrap();
        s.calls += 1;
        match s.crash {
            Some((n, phase)) if s.calls == n => {
                s.crashed = true;
                Some(phase)
            }
            _ => None,
        }
    }

    async fn die(&self) -> ! {
        self.crashed.notify_one();
        std::future::pending::<()>().await;
        unreachable!()
    }
}

#[async_trait]
impl MaintenanceBackend for Durable {
    async fn tracked_records(&self) -> Vec<DhtRecord> {
        if self.enter().is_some() {
            self.die().await;
        }
        vec![self.state.lock().unwrap().record.clone()]
    }

    async fn probe(&self, location: &ShardLocation, _mid: &[u8; 32]) -> ProbeResult {
        if self.enter().is_some() {
            self.die().await;
        }
        let s = self.state.lock().unwrap();
        let holder = holder_id_of(location);
        let outcome = if s.dead.contains(&holder) {
            ProbeOutcome::Unreachable
        } else if s
            .stored
            .get(&holder)
            .is_some_and(|p| p.contains(&(location.segment_index, location.shard_index)))
        {
            ProbeOutcome::Verified
        } else {
            ProbeOutcome::Unverifiable
        };
        ProbeResult { outcome, bytes: 10 }
    }

    async fn source_share(
        &self,
        record: &DhtRecord,
        segment: u32,
        slot: u16,
        _live: &[ShardLocation],
    ) -> Option<MiasmaShare> {
        if self.enter().is_some() {
            self.die().await;
        }
        let s = self.state.lock().unwrap();
        s.local
            .contains(&(segment, slot))
            .then(|| make_share(&record.mid_digest, segment, slot))
    }

    async fn candidates(&self, exclude: &[String]) -> Vec<Candidate> {
        if self.enter().is_some() {
            self.die().await;
        }
        let s = self.state.lock().unwrap();
        s.candidates
            .iter()
            .filter(|c| !exclude.contains(&c.peer_id) && !s.dead.contains(&c.peer_id))
            .cloned()
            .collect()
    }

    async fn push(&self, c: &Candidate, share: &MiasmaShare) -> Result<ShardLocation, String> {
        let phase = self.enter();
        if phase == Some(CrashPhase::Before) {
            self.die().await;
        }
        {
            let mut s = self.state.lock().unwrap();
            if s.dead.contains(&c.peer_id) {
                return Err("holder unreachable".into());
            }
            s.stored
                .entry(c.peer_id.clone())
                .or_default()
                .insert((share.segment_index, share.slot_index));
            s.pushes
                .push((c.peer_id.clone(), share.segment_index, share.slot_index));
        }
        if phase == Some(CrashPhase::After) {
            self.die().await;
        }
        let raw = c.peer_id.strip_prefix("raw:").unwrap();
        Ok(ShardLocation {
            peer_id_bytes: hex::decode(raw).unwrap(),
            shard_index: share.slot_index,
            segment_index: share.segment_index,
            addrs: vec![],
        })
    }

    async fn commit_record(&self, updated: DhtRecord) -> Result<(), String> {
        let phase = self.enter();
        if phase == Some(CrashPhase::Before) {
            self.die().await;
        }
        {
            let mut s = self.state.lock().unwrap();
            if s.fail_commit > 0 {
                s.fail_commit -= 1;
                return Err("busy".into());
            }
            s.commits += 1;
            s.history.push(updated.clone());
            s.record = updated;
        }
        if phase == Some(CrashPhase::After) {
            self.die().await;
        }
        Ok(())
    }
}

pub fn candidate(h: &str) -> Candidate {
    Candidate {
        peer_id: holder_name(h),
        failure_domain: None,
    }
}

pub fn location(segment: u32, slot: u16, holder: &str) -> ShardLocation {
    ShardLocation {
        peer_id_bytes: holder.as_bytes().to_vec(),
        shard_index: slot,
        segment_index: segment,
        addrs: vec!["/ip4/203.0.113.1/tcp/1".to_string()],
    }
}

/// The maintenance settings the unit tests of the executor use: one replica
/// per slot, a single failed probe is enough, no jitter.
pub fn maintenance_cfg() -> MaintenanceConfig {
    MaintenanceConfig {
        planner: PieceMaintenanceConfig {
            target_replicas_per_slot: 1,
            max_actions_per_tick: 8,
            prefer_distinct_failure_domains: false,
            ..PieceMaintenanceConfig::default()
        },
        evidence: EvidenceConfig {
            max_failures: 1,
            ..EvidenceConfig::default()
        },
        backoff: miasma_core::repair::BackoffPolicy {
            base_secs: 100,
            max_secs: 10_000,
            success_cooldown_secs: 500,
            jitter_percent: 0,
        },
        rate_bytes_per_sec: 1_000_000,
        burst_bytes: 10_000_000,
        daily_budget_bytes: 0,
        initial_delay_secs: 0,
        tick_interval_secs: 1,
        max_probes_per_tick: 64,
    }
}
