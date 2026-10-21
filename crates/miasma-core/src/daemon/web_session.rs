//! Signed, scoped sessions for browser pages that call the HTTP bridge.
//!
//! A page does not hold the control token.  It receives a one-time `boot`
//! value (issued over the authenticated IPC and carried in the launch link's
//! fragment), creates a P-256 key pair it cannot export, and registers the
//! public key with `POST /api/session/register`, proving possession of the
//! private key.  Every later request carries
//!
//! ```text
//! Authorization: MiasmaSig v=1, sid=<b64url 16B>, ts=<unix ms>, n=<b64url 16B>, sig=<b64url 64B>
//! ```
//!
//! where `sig` is an ECDSA P-256 / SHA-256 signature (IEEE P1363, `r || s`)
//! over [`canonical_request`].  All binary values are base64url without
//! padding.  Sessions live in memory only: a daemon restart or a wipe ends them.
//!
//! Each limit below is a field of [`Limits`] with the event it prevents; the
//! values are the design defaults and were not measured on a running system.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64U, Engine};
use rand::{rngs::OsRng, Rng};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Scheme name in the `Authorization` header.
pub const AUTH_SCHEME: &str = "MiasmaSig";
/// First line of the registration proof message.
pub const REGISTER_CONTEXT: &str = "miasma-web-register-v1";
/// First line of the signed request string.
pub const SIGN_CONTEXT: &str = "miasma-web-sig-v1";
/// Longest accepted `Authorization` value.
pub const MAX_AUTH_HEADER: usize = 256;
/// Longest accepted registration body.
pub const MAX_REGISTER_BODY: usize = 1024;
/// Values a `GET /api/ping` reply advertises in `web_auth`.
pub const ADVERTISED_AUTH: [&str; 2] = ["bearer", "sig-v1"];

// ─── Scopes ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Read-only state: status, sharing key, transfer list.
    Status,
    /// Publish, retrieve and transfer management.
    Transfer,
    /// Directed sharing.
    Directed,
    /// Wipe.  Never granted to a browser session.
    Destructive,
}

impl Scope {
    fn bit(self) -> u8 {
        match self {
            Scope::Status => 1,
            Scope::Transfer => 2,
            Scope::Directed => 4,
            Scope::Destructive => 8,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Scope::Status => "status",
            Scope::Transfer => "transfer",
            Scope::Directed => "directed",
            Scope::Destructive => "destructive",
        }
    }

    pub fn parse(s: &str) -> Option<Scope> {
        match s {
            "status" => Some(Scope::Status),
            "transfer" => Some(Scope::Transfer),
            "directed" => Some(Scope::Directed),
            "destructive" => Some(Scope::Destructive),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScopeSet(u8);

impl ScopeSet {
    /// What a browser session gets: everything except `destructive`.
    pub const BROWSER_DEFAULT: ScopeSet = ScopeSet(1 | 2 | 4);

    pub fn contains(self, s: Scope) -> bool {
        self.0 & s.bit() != 0
    }

    pub fn names(self) -> Vec<&'static str> {
        [
            Scope::Status,
            Scope::Transfer,
            Scope::Directed,
            Scope::Destructive,
        ]
        .into_iter()
        .filter(|s| self.contains(*s))
        .map(Scope::name)
        .collect()
    }
}

/// The scope a request needs, or `None` when no session may call it.  `None`
/// covers the raw host-path endpoints and every route not listed here, so a
/// route added later is refused for sessions until it is given a scope.
pub fn required_scope(method: &str, path: &str) -> Option<Scope> {
    match (method, path) {
        ("GET", "/api/status")
        | ("GET", "/api/sharing-key")
        | ("GET", "/api/session")
        | ("POST", "/api/session/end") => Some(Scope::Status),

        ("POST", "/api/publish") | ("POST", "/api/retrieve") => Some(Scope::Transfer),

        ("POST", "/api/directed/send")
        | ("POST", "/api/directed/confirm")
        | ("POST", "/api/directed/retrieve")
        | ("POST", "/api/directed/revoke")
        | ("GET", "/api/directed/inbox")
        | ("GET", "/api/directed/outbox") => Some(Scope::Directed),

        ("POST", "/api/wipe") => Some(Scope::Destructive),

        (m, p) if p == "/api/transfers" || p.starts_with("/api/transfers/") => {
            let rest = p.strip_prefix("/api/transfers")?;
            let segs: Vec<&str> = match rest.strip_prefix('/') {
                None if rest.is_empty() => Vec::new(),
                None => return None,
                Some(r) => r.split('/').collect(),
            };
            match (m, segs.as_slice()) {
                ("GET", []) => Some(Scope::Status),
                ("GET", [id]) if !id.is_empty() => Some(Scope::Status),
                ("POST", ["receive"]) | ("POST", ["clear-finished"]) => Some(Scope::Transfer),
                ("POST", [id, "cancel"]) | ("POST", [id, "remove"]) if !id.is_empty() => {
                    Some(Scope::Transfer)
                }
                _ => None,
            }
        }

        _ => None,
    }
}

// ─── Refusals ────────────────────────────────────────────────────────────────

/// Why a request was turned away: HTTP status, a stable `code`, and a sentence
/// that says what to do next (older pages show only this sentence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
    /// One extra JSON member (`server_time_ms`, `needed`).
    pub extra: Option<(&'static str, serde_json::Value)>,
}

fn refuse(status: u16, code: &'static str, message: &str) -> Refusal {
    Refusal {
        status,
        code,
        message: message.to_owned(),
        extra: None,
    }
}

const RERUN: &str = "run `miasma web` again to open a new session";

// ─── Clock and limits ────────────────────────────────────────────────────────

/// Time source; tests substitute a fake one.
pub trait Clock: Send + Sync {
    /// Monotonic time, for lifetimes.
    fn now(&self) -> Instant;
    /// Wall clock in unix milliseconds, for request timestamps.
    fn unix_ms(&self) -> i64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn unix_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

/// Bounds on the session table.  Defaults are the design values; none was
/// measured on a running system.
#[derive(Debug, Clone)]
pub struct Limits {
    /// How long a `boot` value is valid.  Prevents a link that was printed,
    /// copied or left in a history from opening a session later.
    pub boot_ttl: Duration,
    /// Outstanding `boot` values.  Prevents the table growing without bound
    /// under repeated `miasma web`; the oldest is replaced.
    pub max_pending: usize,
    /// Used `boot` values remembered for double-use detection.
    pub max_consumed: usize,
    /// Live sessions.  Prevents unbounded memory (each holds a nonce table);
    /// a new registration is refused instead of evicting an open tab.
    pub max_sessions: usize,
    /// A session unused this long ends.  Prevents a forgotten tab staying usable.
    pub idle_timeout: Duration,
    /// A session ends this long after creation, however busy.
    pub max_lifetime: Duration,
    /// Request nonces remembered per session.  Prevents replay of a captured
    /// request within the timestamp window while bounding memory; when full,
    /// requests get 429 rather than forgetting the oldest nonce.
    pub nonce_capacity: usize,
    /// How long a nonce is remembered: the timestamp window (`ts_past` +
    /// `ts_future`), after which a replay fails on its timestamp alone.
    pub nonce_retention: Duration,
    /// Accepted request age.
    pub ts_past: Duration,
    /// Accepted request lead over the daemon clock.
    pub ts_future: Duration,
    /// Failed signatures after which a session ends.  A genuine client does
    /// not fail; this stops guessing against a live session.
    pub max_bad_signatures: u32,
    /// Failed proofs of possession after which a `boot` value is voided.
    pub max_boot_failures: u8,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            boot_ttl: Duration::from_secs(60),
            max_pending: 4,
            max_consumed: 16,
            max_sessions: 8,
            idle_timeout: Duration::from_secs(15 * 60),
            max_lifetime: Duration::from_secs(12 * 60 * 60),
            nonce_capacity: 1024,
            nonce_retention: Duration::from_secs(70),
            ts_past: Duration::from_secs(60),
            ts_future: Duration::from_secs(10),
            max_bad_signatures: 10,
            max_boot_failures: 3,
        }
    }
}

// ─── Encoding helpers ────────────────────────────────────────────────────────

/// Decode exactly `N` bytes of canonical base64url (no padding).
fn dec<const N: usize>(s: &str) -> Option<[u8; N]> {
    let v = B64U.decode(s).ok()?;
    if v.len() != N || B64U.encode(&v) != s {
        return None;
    }
    v.try_into().ok()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Lower-case hex SHA-256 of a request body.
pub fn body_hash_hex(body: &[u8]) -> String {
    hex::encode(sha256(body))
}

/// The string a request signature covers.  `origin` is the origin registered
/// for the session; `sid` and `nonce` are their base64url texts.
pub fn canonical_request(
    method: &str,
    path_and_query: &str,
    origin: &str,
    sid: &str,
    ts: i64,
    nonce: &str,
    body: &[u8],
) -> String {
    format!(
        "{SIGN_CONTEXT}\n{method}\n{path_and_query}\n{origin}\n{sid}\n{ts}\n{nonce}\n{}",
        body_hash_hex(body)
    )
}

/// The string a registration proof of possession covers.
pub fn register_message(origin: &str, boot: &str, public_key: &str, ts: i64) -> String {
    format!("{REGISTER_CONTEXT}\n{origin}\n{boot}\n{public_key}\n{ts}")
}

/// Verify an ECDSA P-256 / SHA-256 signature (`r || s`, 64 bytes) by an
/// uncompressed public key (65 bytes).
pub fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key)
        .verify(message, signature)
        .is_ok()
}

// ─── Header ──────────────────────────────────────────────────────────────────

/// A parsed `Authorization: MiasmaSig ...` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigHeader {
    pub sid: [u8; 16],
    pub ts: i64,
    pub nonce: [u8; 16],
    pub signature: [u8; 64],
}

impl SigHeader {
    /// The value after the scheme name; the syntax is strict (fixed order,
    /// `, ` separators, canonical base64url).
    pub fn parse(value: &str) -> Result<SigHeader, Refusal> {
        let bad = || refuse(401, "bad_auth_header", "malformed Authorization header");
        if value.len() > MAX_AUTH_HEADER {
            return Err(bad());
        }
        let rest = value
            .strip_prefix(AUTH_SCHEME)
            .and_then(|r| r.strip_prefix(' '))
            .ok_or_else(bad)?;
        let mut parts = rest.split(", ");
        let v = parts
            .next()
            .and_then(|p| p.strip_prefix("v="))
            .ok_or_else(bad)?;
        if v != "1" {
            return Err(bad());
        }
        let sid = parts
            .next()
            .and_then(|p| p.strip_prefix("sid="))
            .ok_or_else(bad)?;
        let ts = parts
            .next()
            .and_then(|p| p.strip_prefix("ts="))
            .ok_or_else(bad)?;
        let n = parts
            .next()
            .and_then(|p| p.strip_prefix("n="))
            .ok_or_else(bad)?;
        let sig = parts
            .next()
            .and_then(|p| p.strip_prefix("sig="))
            .ok_or_else(bad)?;
        if parts.next().is_some() {
            return Err(bad());
        }
        if ts.is_empty() || ts.len() > 16 || !ts.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        Ok(SigHeader {
            sid: dec(sid).ok_or_else(bad)?,
            ts: ts.parse().map_err(|_| bad())?,
            nonce: dec(n).ok_or_else(bad)?,
            signature: dec(sig).ok_or_else(bad)?,
        })
    }

    pub fn sid_text(&self) -> String {
        B64U.encode(self.sid)
    }

    pub fn nonce_text(&self) -> String {
        B64U.encode(self.nonce)
    }
}

// ─── State ───────────────────────────────────────────────────────────────────

struct PendingBoot {
    hash: [u8; 32],
    origin: String,
    scopes: ScopeSet,
    issued: Instant,
    failures: u8,
}

struct ConsumedBoot {
    hash: [u8; 32],
    until: Instant,
    session: [u8; 16],
}

struct Session {
    origin: String,
    pubkey: [u8; 65],
    scopes: ScopeSet,
    created: Instant,
    last_used: Instant,
    seen: HashSet<[u8; 16]>,
    order: VecDeque<(Instant, [u8; 16])>,
    bad_sigs: u32,
}

#[derive(Default)]
struct Inner {
    pending: Vec<PendingBoot>,
    consumed: VecDeque<ConsumedBoot>,
    sessions: HashMap<[u8; 16], Session>,
    /// Ids of sessions that ended by timeout, so the page can be told so.
    expired: VecDeque<[u8; 16]>,
}

const MAX_EXPIRED_REMEMBERED: usize = 32;

/// What a successful registration returns to the page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    pub sid: String,
    pub scopes: ScopeSet,
    pub idle_timeout_s: u64,
    pub expires_in_s: u64,
    pub server_time_ms: i64,
}

/// One live session as `WebSessionList` reports it (no key material).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSessionInfo {
    /// First four characters of the session id.
    pub sid_prefix: String,
    pub origin: String,
    pub scopes: Vec<String>,
    pub idle_expires_in_s: u64,
    pub expires_in_s: u64,
}

pub struct WebSessions {
    inner: Mutex<Inner>,
    limits: Limits,
    clock: Arc<dyn Clock>,
    browser_bearer: AtomicU64,
}

impl Default for WebSessions {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBody {
    v: u32,
    boot: String,
    #[serde(rename = "pub")]
    public: String,
    ts: i64,
    pop: String,
}

impl WebSessions {
    pub fn new() -> Self {
        Self::with_limits_and_clock(Limits::default(), Arc::new(SystemClock))
    }

    pub fn with_limits_and_clock(limits: Limits, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            limits,
            clock,
            browser_bearer: AtomicU64::new(0),
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn is_expired(&self, s: &Session, now: Instant) -> bool {
        now.saturating_duration_since(s.last_used) > self.limits.idle_timeout
            || now.saturating_duration_since(s.created) > self.limits.max_lifetime
    }

    /// End every session that timed out, remembering its id.
    fn sweep(&self, inner: &mut Inner, now: Instant) {
        let gone: Vec<[u8; 16]> = inner
            .sessions
            .iter()
            .filter(|(_, s)| self.is_expired(s, now))
            .map(|(id, _)| *id)
            .collect();
        for id in gone {
            inner.sessions.remove(&id);
            inner.expired.push_back(id);
            while inner.expired.len() > MAX_EXPIRED_REMEMBERED {
                inner.expired.pop_front();
            }
        }
        while inner.consumed.front().is_some_and(|c| c.until < now) {
            inner.consumed.pop_front();
        }
    }

    // ── Bootstrap ────────────────────────────────────────────────────────────

    /// Issue a one-time `boot` value for `origin` (an `http(s)` loopback
    /// origin).  `scopes` empty means the browser default; `destructive` and
    /// unknown names are refused.  Returns the value and its lifetime.
    pub fn issue_boot(
        &self,
        origin: &str,
        scopes: &[String],
    ) -> Result<(Zeroizing<String>, u32), String> {
        let origin = super::web_guard::loopback_origin(origin, &["http", "https"])
            .ok_or_else(|| "origin must be an http(s) origin on this computer".to_owned())?;
        let set = if scopes.is_empty() {
            ScopeSet::BROWSER_DEFAULT
        } else {
            let mut bits = 0u8;
            for s in scopes {
                match Scope::parse(s) {
                    Some(Scope::Destructive) => {
                        return Err(
                            "the destructive scope is not available to browser sessions".into()
                        )
                    }
                    Some(sc) => bits |= sc.bit(),
                    None => return Err(format!("unknown scope {s:?}")),
                }
            }
            ScopeSet(bits)
        };
        let raw: Zeroizing<[u8; 32]> = Zeroizing::new(OsRng.gen());
        let boot = Zeroizing::new(B64U.encode(raw.as_slice()));
        let now = self.clock.now();
        let mut inner = self.lock();
        let ttl = self.limits.boot_ttl;
        inner
            .pending
            .retain(|p| now.saturating_duration_since(p.issued) <= ttl);
        while inner.pending.len() >= self.limits.max_pending.max(1) {
            inner.pending.remove(0);
        }
        inner.pending.push(PendingBoot {
            hash: sha256(raw.as_slice()),
            origin,
            scopes: set,
            issued: now,
            failures: 0,
        });
        Ok((boot, ttl.as_secs() as u32))
    }

    // ── Registration ─────────────────────────────────────────────────────────

    fn window_check(&self, ts: i64) -> Result<(), Refusal> {
        let now_ms = self.clock.unix_ms();
        let lo = now_ms - self.limits.ts_past.as_millis() as i64;
        let hi = now_ms + self.limits.ts_future.as_millis() as i64;
        if ts < lo || ts > hi {
            return Err(Refusal {
                status: 401,
                code: "stale_timestamp",
                message: "request time is outside the accepted window; retry with the server time"
                    .into(),
                extra: Some(("server_time_ms", now_ms.into())),
            });
        }
        Ok(())
    }

    /// `POST /api/session/register`.  `origin` is the validated `Origin` of the
    /// request.
    pub fn register(&self, origin: Option<&str>, body: &[u8]) -> Result<Registered, Refusal> {
        let origin = origin.ok_or_else(|| {
            refuse(
                403,
                "origin_required",
                "registration must come from a browser page",
            )
        })?;
        if body.len() > MAX_REGISTER_BODY {
            return Err(refuse(400, "bad_request", "registration body too large"));
        }
        let req: RegisterBody = serde_json::from_slice(body)
            .map_err(|_| refuse(400, "bad_request", "invalid registration body"))?;
        if req.v != 1 {
            return Err(refuse(400, "bad_request", "unsupported session version"));
        }

        let now = self.clock.now();
        let mut inner = self.lock();
        self.sweep(&mut inner, now);

        let invalid = || refuse(401, "boot_invalid", &format!("link not valid: {RERUN}"));
        let boot_raw: [u8; 32] = dec(&req.boot).ok_or_else(invalid)?;
        let hash = sha256(&boot_raw);

        let idx = inner
            .pending
            .iter()
            .position(|p| p.hash.ct_eq(&hash).unwrap_u8() == 1);
        let Some(idx) = idx else {
            // A value that was already used: end the session it opened.
            if let Some(c) = inner
                .consumed
                .iter()
                .find(|c| c.hash.ct_eq(&hash).unwrap_u8() == 1)
            {
                let sid = c.session;
                inner.sessions.remove(&sid);
                warn!("web session: a bootstrap value was presented twice; its session was ended");
                return Err(refuse(
                    401,
                    "boot_already_used",
                    &format!("link already used: {RERUN}"),
                ));
            }
            return Err(invalid());
        };

        if now.saturating_duration_since(inner.pending[idx].issued) > self.limits.boot_ttl {
            inner.pending.remove(idx);
            return Err(refuse(
                401,
                "boot_expired",
                &format!("link expired: {RERUN}"),
            ));
        }
        if inner.pending[idx].origin != origin {
            return Err(refuse(
                403,
                "origin_mismatch",
                "this link was issued for a different page address",
            ));
        }

        let pubkey: [u8; 65] = dec(&req.public)
            .filter(|k: &[u8; 65]| k[0] == 0x04)
            .ok_or_else(|| refuse(400, "bad_public_key", "invalid public key"))?;
        self.window_check(req.ts)?;

        let message = register_message(origin, &req.boot, &req.public, req.ts);
        let proof_ok = dec::<64>(&req.pop)
            .map(|sig| verify_signature(&pubkey, message.as_bytes(), &sig))
            .unwrap_or(false);
        if !proof_ok {
            let p = &mut inner.pending[idx];
            p.failures = p.failures.saturating_add(1);
            if p.failures >= self.limits.max_boot_failures {
                inner.pending.remove(idx);
            }
            return Err(refuse(
                401,
                "bad_signature",
                "proof of possession did not verify",
            ));
        }

        if inner.sessions.values().any(|s| s.pubkey == pubkey) {
            return Err(refuse(409, "key_reused", "this key is already registered"));
        }
        if inner.sessions.len() >= self.limits.max_sessions {
            return Err(refuse(
                429,
                "too_many_sessions",
                "too many open sessions: close one with `miasma web --revoke` or wait",
            ));
        }

        let boot = inner.pending.remove(idx);
        let sid: [u8; 16] = OsRng.gen();
        inner.consumed.push_back(ConsumedBoot {
            hash: boot.hash,
            until: now + self.limits.boot_ttl,
            session: sid,
        });
        while inner.consumed.len() > self.limits.max_consumed {
            inner.consumed.pop_front();
        }
        inner.sessions.insert(
            sid,
            Session {
                origin: boot.origin,
                pubkey,
                scopes: boot.scopes,
                created: now,
                last_used: now,
                seen: HashSet::new(),
                order: VecDeque::new(),
                bad_sigs: 0,
            },
        );
        let short = B64U.encode(sid)[..4].to_owned();
        debug!(sid = %short, "web session registered");
        Ok(Registered {
            sid: B64U.encode(sid),
            scopes: boot.scopes,
            idle_timeout_s: self.limits.idle_timeout.as_secs(),
            expires_in_s: self.limits.max_lifetime.as_secs(),
            server_time_ms: self.clock.unix_ms(),
        })
    }

    // ── Requests ─────────────────────────────────────────────────────────────

    /// The checks that need no body and no signature: session, origin,
    /// timestamp, nonce, scope.  Run before the body is read.
    pub fn precheck(
        &self,
        h: &SigHeader,
        origin: Option<&str>,
        needed: Scope,
    ) -> Result<(), Refusal> {
        let now = self.clock.now();
        let mut inner = self.lock();
        self.sweep(&mut inner, now);
        let s = self.lookup(&mut inner, h, now)?;
        if let Some(o) = origin {
            if o != s.origin {
                return Err(refuse(
                    403,
                    "origin_mismatch",
                    "request origin differs from the session's",
                ));
            }
        }
        self.window_check(h.ts)?;
        self.nonce_check(s, h, now)?;
        if !s.scopes.contains(needed) {
            return Err(Refusal {
                status: 403,
                code: "scope_required",
                message: "this session may not do that".into(),
                extra: Some(("needed", needed.name().into())),
            });
        }
        Ok(())
    }

    fn lookup<'a>(
        &self,
        inner: &'a mut Inner,
        h: &SigHeader,
        _now: Instant,
    ) -> Result<&'a mut Session, Refusal> {
        if !inner.sessions.contains_key(&h.sid) {
            return Err(if inner.expired.contains(&h.sid) {
                refuse(401, "session_expired", &format!("session expired: {RERUN}"))
            } else {
                refuse(401, "session_unknown", &format!("unknown session: {RERUN}"))
            });
        }
        Ok(inner.sessions.get_mut(&h.sid).expect("checked above"))
    }

    fn nonce_check(&self, s: &mut Session, h: &SigHeader, now: Instant) -> Result<(), Refusal> {
        let keep = self.limits.nonce_retention;
        while let Some((at, n)) = s.order.front().copied() {
            if now.saturating_duration_since(at) > keep {
                s.order.pop_front();
                s.seen.remove(&n);
            } else {
                break;
            }
        }
        if s.seen.contains(&h.nonce) {
            return Err(refuse(401, "replayed_nonce", "request already used"));
        }
        if s.seen.len() >= self.limits.nonce_capacity {
            return Err(refuse(
                429,
                "nonce_cache_full",
                "too many requests in a short time; retry in a moment",
            ));
        }
        Ok(())
    }

    /// Verify the signature over the request and, on success, record the
    /// nonce and extend the idle timeout.  Repeats the cheap checks, because
    /// the session may have changed while the body was read.
    pub fn verify(
        &self,
        h: &SigHeader,
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> Result<ScopeSet, Refusal> {
        let now = self.clock.now();
        let mut inner = self.lock();
        self.sweep(&mut inner, now);
        let s = self.lookup(&mut inner, h, now)?;
        self.window_check(h.ts)?;
        self.nonce_check(s, h, now)?;

        let message = canonical_request(
            method,
            path_and_query,
            &s.origin,
            &h.sid_text(),
            h.ts,
            &h.nonce_text(),
            body,
        );
        if !verify_signature(&s.pubkey, message.as_bytes(), &h.signature) {
            s.bad_sigs += 1;
            if s.bad_sigs >= self.limits.max_bad_signatures {
                inner.sessions.remove(&h.sid);
                warn!("web session ended after repeated bad signatures");
            }
            return Err(refuse(401, "bad_signature", "signature did not verify"));
        }
        s.bad_sigs = 0;
        s.last_used = now;
        s.seen.insert(h.nonce);
        s.order.push_back((now, h.nonce));
        Ok(s.scopes)
    }

    // ── Management ───────────────────────────────────────────────────────────

    /// End the session `sid`.  Returns whether it existed.
    pub fn end(&self, sid: &[u8; 16]) -> bool {
        self.lock().sessions.remove(sid).is_some()
    }

    /// End every session and void every outstanding `boot` value.
    pub fn revoke_all(&self) -> usize {
        let mut inner = self.lock();
        let n = inner.sessions.len();
        inner.sessions.clear();
        inner.pending.clear();
        inner.consumed.clear();
        n
    }

    /// End the sessions whose id starts with `prefix` (at least four
    /// characters).  `None` ends all of them.
    pub fn revoke(&self, prefix: Option<&str>) -> usize {
        match prefix {
            None => self.revoke_all(),
            Some(p) if p.len() < 4 => 0,
            Some(p) => {
                let mut inner = self.lock();
                let ids: Vec<[u8; 16]> = inner
                    .sessions
                    .keys()
                    .filter(|id| B64U.encode(id).starts_with(p))
                    .copied()
                    .collect();
                for id in &ids {
                    inner.sessions.remove(id);
                }
                ids.len()
            }
        }
    }

    fn info_of(&self, id: &[u8; 16], s: &Session, now: Instant) -> WebSessionInfo {
        let idle = self
            .limits
            .idle_timeout
            .saturating_sub(now.saturating_duration_since(s.last_used));
        let life = self
            .limits
            .max_lifetime
            .saturating_sub(now.saturating_duration_since(s.created));
        WebSessionInfo {
            sid_prefix: B64U.encode(id)[..4].to_owned(),
            origin: s.origin.clone(),
            scopes: s.scopes.names().into_iter().map(str::to_owned).collect(),
            idle_expires_in_s: idle.as_secs(),
            expires_in_s: life.as_secs(),
        }
    }

    pub fn list(&self) -> Vec<WebSessionInfo> {
        let now = self.clock.now();
        let mut inner = self.lock();
        self.sweep(&mut inner, now);
        let mut v: Vec<WebSessionInfo> = inner
            .sessions
            .iter()
            .map(|(id, s)| self.info_of(id, s, now))
            .collect();
        v.sort_by(|a, b| a.sid_prefix.cmp(&b.sid_prefix));
        v
    }

    /// The caller's own session, for `GET /api/session`.
    pub fn info(&self, sid: &[u8; 16]) -> Option<WebSessionInfo> {
        let now = self.clock.now();
        let inner = self.lock();
        inner.sessions.get(sid).map(|s| self.info_of(sid, s, now))
    }

    /// Count a browser request that used the control token as a Bearer.
    /// Returns the new total.
    pub fn note_browser_bearer(&self) -> u64 {
        self.browser_bearer.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn browser_bearer_count(&self) -> u64 {
        self.browser_bearer.load(Ordering::Relaxed)
    }

    /// Number of live sessions and outstanding boot values.
    pub fn counts(&self) -> (usize, usize) {
        let inner = self.lock();
        (inner.sessions.len(), inner.pending.len())
    }

    /// Estimate of the heap held by the tables (capacities times entry
    /// sizes); an estimate, not an allocator measurement.
    pub fn approx_bytes(&self) -> usize {
        let inner = self.lock();
        let mut total = inner.pending.capacity() * std::mem::size_of::<PendingBoot>()
            + inner.consumed.capacity() * std::mem::size_of::<ConsumedBoot>();
        for s in inner.sessions.values() {
            total += std::mem::size_of::<Session>()
                + s.origin.capacity()
                + s.seen.capacity() * (std::mem::size_of::<[u8; 16]>() + 1)
                + s.order.capacity() * std::mem::size_of::<(Instant, [u8; 16])>();
        }
        total
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
    };
    use std::sync::atomic::AtomicI64;

    const ORIGIN: &str = "http://127.0.0.1:17842";

    struct FakeClock {
        base: Instant,
        start_ms: i64,
        elapsed_ms: AtomicI64,
    }

    impl FakeClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                base: Instant::now(),
                start_ms: 1_800_000_000_000,
                elapsed_ms: AtomicI64::new(0),
            })
        }
        fn advance(&self, d: Duration) {
            self.elapsed_ms
                .fetch_add(d.as_millis() as i64, Ordering::SeqCst);
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.base + Duration::from_millis(self.elapsed_ms.load(Ordering::SeqCst) as u64)
        }
        fn unix_ms(&self) -> i64 {
            self.start_ms + self.elapsed_ms.load(Ordering::SeqCst)
        }
    }

    /// A signing client with a key generated at run time.
    struct Client {
        kp: EcdsaKeyPair,
        rng: SystemRandom,
        sid: String,
    }

    impl Client {
        fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            let kp =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            Self {
                kp,
                rng,
                sid: String::new(),
            }
        }
        fn public(&self) -> String {
            B64U.encode(self.kp.public_key().as_ref())
        }
        fn sign(&self, msg: &str) -> [u8; 64] {
            self.kp
                .sign(&self.rng, msg.as_bytes())
                .unwrap()
                .as_ref()
                .try_into()
                .unwrap()
        }
        fn register_body(&self, boot: &str, ts: i64) -> Vec<u8> {
            let public = self.public();
            let pop = B64U.encode(self.sign(&register_message(ORIGIN, boot, &public, ts)));
            serde_json::to_vec(&serde_json::json!({
                "v": 1, "boot": boot, "pub": public, "ts": ts, "pop": pop
            }))
            .unwrap()
        }
        fn header(&self, method: &str, pq: &str, body: &[u8], ts: i64) -> SigHeader {
            let n: [u8; 16] = OsRng.gen();
            self.header_with_nonce(method, pq, body, ts, n)
        }
        fn header_with_nonce(
            &self,
            method: &str,
            pq: &str,
            body: &[u8],
            ts: i64,
            n: [u8; 16],
        ) -> SigHeader {
            let canon = canonical_request(method, pq, ORIGIN, &self.sid, ts, &B64U.encode(n), body);
            SigHeader {
                sid: dec(&self.sid).unwrap(),
                ts,
                nonce: n,
                signature: self.sign(&canon),
            }
        }
    }

    fn sessions() -> (WebSessions, Arc<FakeClock>) {
        let clock = FakeClock::new();
        (
            WebSessions::with_limits_and_clock(Limits::default(), clock.clone()),
            clock,
        )
    }

    fn open(ws: &WebSessions, clock: &FakeClock) -> Client {
        let (boot, _) = ws.issue_boot(ORIGIN, &[]).unwrap();
        let mut c = Client::new();
        let r = ws
            .register(Some(ORIGIN), &c.register_body(&boot, clock.unix_ms()))
            .unwrap();
        c.sid = r.sid;
        c
    }

    #[test]
    fn registration_creates_a_session_and_consumes_the_boot() {
        let (ws, clock) = sessions();
        let (boot, ttl) = ws.issue_boot(ORIGIN, &[]).unwrap();
        assert_eq!(ttl, 60);
        let c = Client::new();
        let body = c.register_body(&boot, clock.unix_ms());
        let r = ws.register(Some(ORIGIN), &body).unwrap();
        assert_eq!(r.scopes, ScopeSet::BROWSER_DEFAULT);
        assert_eq!(r.idle_timeout_s, 900);
        assert_eq!(r.expires_in_s, 43_200);
        assert_eq!(ws.counts(), (1, 0));
        // The same body again is a second use of the value.
        let e = ws.register(Some(ORIGIN), &body).unwrap_err();
        assert_eq!(e.code, "boot_already_used");
    }

    #[test]
    fn a_replayed_boot_ends_the_session_it_opened() {
        let (ws, clock) = sessions();
        let (boot, _) = ws.issue_boot(ORIGIN, &[]).unwrap();
        let mut honest = Client::new();
        honest.sid = ws
            .register(Some(ORIGIN), &honest.register_body(&boot, clock.unix_ms()))
            .unwrap()
            .sid;
        let h = honest.header("GET", "/api/status", b"", clock.unix_ms());
        assert!(ws.verify(&h, "GET", "/api/status", b"").is_ok());

        let attacker = Client::new();
        let e = ws
            .register(
                Some(ORIGIN),
                &attacker.register_body(&boot, clock.unix_ms()),
            )
            .unwrap_err();
        assert_eq!(e.code, "boot_already_used");
        let h = honest.header("GET", "/api/status", b"", clock.unix_ms());
        assert_eq!(
            ws.precheck(&h, None, Scope::Status).unwrap_err().code,
            "session_unknown"
        );
    }

    #[test]
    fn registration_refusals() {
        let (ws, clock) = sessions();
        let (boot, _) = ws.issue_boot(ORIGIN, &[]).unwrap();
        let c = Client::new();
        let now = clock.unix_ms();
        let body = c.register_body(&boot, now);
        // No Origin, other Origin.
        assert_eq!(
            ws.register(None, &body).unwrap_err().code,
            "origin_required"
        );
        assert_eq!(
            ws.register(Some("http://127.0.0.1:9"), &body)
                .unwrap_err()
                .code,
            "origin_mismatch"
        );
        // Unknown boot.
        let other: [u8; 32] = OsRng.gen();
        let e = ws
            .register(Some(ORIGIN), &c.register_body(&B64U.encode(other), now))
            .unwrap_err();
        assert_eq!(e.code, "boot_invalid");
        // Proof made by another key.
        let thief = Client::new();
        let mut forged: serde_json::Value = serde_json::from_slice(&body).unwrap();
        forged["pop"] = B64U
            .encode(thief.sign(&register_message(ORIGIN, &boot, &c.public(), now)))
            .into();
        let e = ws
            .register(Some(ORIGIN), &serde_json::to_vec(&forged).unwrap())
            .unwrap_err();
        assert_eq!(e.code, "bad_signature");
        // Three failures void the value, even for the right key.
        for _ in 0..2 {
            let _ = ws.register(Some(ORIGIN), &serde_json::to_vec(&forged).unwrap());
        }
        assert_eq!(
            ws.register(Some(ORIGIN), &body).unwrap_err().code,
            "boot_invalid"
        );
        // Stale timestamp.
        let (boot2, _) = ws.issue_boot(ORIGIN, &[]).unwrap();
        let e = ws
            .register(Some(ORIGIN), &c.register_body(&boot2, now - 61_000))
            .unwrap_err();
        assert_eq!(e.code, "stale_timestamp");
        assert!(e.extra.is_some());
        // Bad key shape and unknown fields.
        let mut v: serde_json::Value =
            serde_json::from_slice(&c.register_body(&boot2, now)).unwrap();
        v["pub"] = B64U.encode([4u8; 10]).into();
        assert_eq!(
            ws.register(Some(ORIGIN), &serde_json::to_vec(&v).unwrap())
                .unwrap_err()
                .code,
            "bad_public_key"
        );
        let mut v: serde_json::Value =
            serde_json::from_slice(&c.register_body(&boot2, now)).unwrap();
        v["extra"] = 1.into();
        assert_eq!(
            ws.register(Some(ORIGIN), &serde_json::to_vec(&v).unwrap())
                .unwrap_err()
                .code,
            "bad_request"
        );
        // Oversized body.
        assert_eq!(
            ws.register(Some(ORIGIN), &vec![b' '; MAX_REGISTER_BODY + 1])
                .unwrap_err()
                .code,
            "bad_request"
        );
        // Expired boot.
        let (boot3, _) = ws.issue_boot(ORIGIN, &[]).unwrap();
        clock.advance(Duration::from_secs(61));
        let e = ws
            .register(Some(ORIGIN), &c.register_body(&boot3, clock.unix_ms()))
            .unwrap_err();
        assert_eq!(e.code, "boot_expired");
    }

    #[test]
    fn the_same_key_cannot_open_two_sessions() {
        let (ws, clock) = sessions();
        let c = open(&ws, &clock);
        let (boot, _) = ws.issue_boot(ORIGIN, &[]).unwrap();
        let e = ws
            .register(Some(ORIGIN), &c.register_body(&boot, clock.unix_ms()))
            .unwrap_err();
        assert_eq!(e.code, "key_reused");
    }

    #[test]
    fn signature_accept_and_reject_cases() {
        let (ws, clock) = sessions();
        let c = open(&ws, &clock);
        let now = clock.unix_ms();
        let body = br#"{"data":"AAAA"}"#;
        let h = c.header("POST", "/api/publish?x=1", body, now);
        assert!(ws.precheck(&h, Some(ORIGIN), Scope::Transfer).is_ok());
        assert!(ws.verify(&h, "POST", "/api/publish?x=1", body).is_ok());

        let bad = |h: &SigHeader, m: &str, p: &str, b: &[u8]| -> &'static str {
            ws.verify(h, m, p, b).unwrap_err().code
        };
        // Tampered body, path, method.
        let h = c.header("POST", "/api/publish", body, now);
        assert_eq!(
            bad(&h, "POST", "/api/publish", b"{\"data\":\"AAAB\"}"),
            "bad_signature"
        );
        let h = c.header("POST", "/api/publish", body, now);
        assert_eq!(bad(&h, "POST", "/api/retrieve", body), "bad_signature");
        let h = c.header("POST", "/api/publish", body, now);
        assert_eq!(bad(&h, "GET", "/api/publish", body), "bad_signature");
        // One flipped bit in the signature.
        let mut h = c.header("POST", "/api/publish", body, now);
        h.signature[10] ^= 1;
        assert_eq!(bad(&h, "POST", "/api/publish", body), "bad_signature");
        // Another key.
        let mut other = Client::new();
        other.sid = c.sid.clone();
        let h = other.header("POST", "/api/publish", body, now);
        assert_eq!(bad(&h, "POST", "/api/publish", body), "bad_signature");
        // A different session id.
        let mut h = c.header("POST", "/api/publish", body, now);
        h.sid = OsRng.gen();
        assert_eq!(bad(&h, "POST", "/api/publish", body), "session_unknown");
        // A different origin on the request.
        let h = c.header("POST", "/api/publish", body, now);
        assert_eq!(
            ws.precheck(&h, Some("http://localhost:1"), Scope::Transfer)
                .unwrap_err()
                .code,
            "origin_mismatch"
        );
    }

    #[test]
    fn timestamp_window() {
        let (ws, clock) = sessions();
        let c = open(&ws, &clock);
        let now = clock.unix_ms();
        for (ts, ok) in [
            (now, true),
            (now - 59_000, true),
            (now + 9_000, true),
            (now - 61_000, false),
            (now + 11_000, false),
        ] {
            let h = c.header("GET", "/api/status", b"", ts);
            let r = ws.verify(&h, "GET", "/api/status", b"");
            assert_eq!(r.is_ok(), ok, "ts offset {}", ts - now);
            if !ok {
                let e = r.unwrap_err();
                assert_eq!(e.code, "stale_timestamp");
                assert_eq!(e.extra.unwrap().0, "server_time_ms");
            }
        }
    }

    #[test]
    fn a_nonce_cannot_be_reused_and_the_table_is_bounded() {
        let (ws, clock) = sessions();
        let c = open(&ws, &clock);
        let now = clock.unix_ms();
        let n: [u8; 16] = OsRng.gen();
        let h = c.header_with_nonce("GET", "/api/status", b"", now, n);
        assert!(ws.verify(&h, "GET", "/api/status", b"").is_ok());
        assert_eq!(
            ws.verify(&h, "GET", "/api/status", b"").unwrap_err().code,
            "replayed_nonce"
        );

        // Fill the table (one is used already).
        for _ in 0..1023 {
            let h = c.header("GET", "/api/status", b"", now);
            ws.verify(&h, "GET", "/api/status", b"").unwrap();
        }
        let h = c.header("GET", "/api/status", b"", now);
        let e = ws.precheck(&h, None, Scope::Status).unwrap_err();
        assert_eq!((e.status, e.code), (429, "nonce_cache_full"));
        let e = ws.verify(&h, "GET", "/api/status", b"").unwrap_err();
        assert_eq!(e.status, 429);
        // Memory estimate for a full table (recorded, not asserted tightly).
        let bytes = ws.approx_bytes();
        eprintln!("full nonce table, one session: about {bytes} bytes");
        assert!(bytes < 128 * 1024, "{bytes}");
        // Nothing was forgotten: the old nonce still counts as used.
        let h = c.header_with_nonce("GET", "/api/status", b"", now, n);
        assert_eq!(
            ws.precheck(&h, None, Scope::Status).unwrap_err().code,
            "replayed_nonce"
        );
        // After the retention time the table frees up.
        clock.advance(Duration::from_secs(71));
        let h = c.header("GET", "/api/status", b"", clock.unix_ms());
        assert!(ws.verify(&h, "GET", "/api/status", b"").is_ok());
    }

    #[test]
    fn scopes_are_enforced_and_destructive_is_never_granted() {
        let (ws, clock) = sessions();
        let c = open(&ws, &clock);
        let now = clock.unix_ms();
        let h = c.header("POST", "/api/wipe", b"", now);
        let e = ws.precheck(&h, None, Scope::Destructive).unwrap_err();
        assert_eq!((e.status, e.code), (403, "scope_required"));
        assert_eq!(e.extra.unwrap().1, "destructive");
        assert!(ws.issue_boot(ORIGIN, &["destructive".to_owned()]).is_err());
        assert!(ws.issue_boot(ORIGIN, &["bogus".to_owned()]).is_err());
        assert!(ws.issue_boot("https://evil.example", &[]).is_err());

        // A narrower session.
        let (boot, _) = ws.issue_boot(ORIGIN, &["status".to_owned()]).unwrap();
        let mut n = Client::new();
        n.sid = ws
            .register(Some(ORIGIN), &n.register_body(&boot, now))
            .unwrap()
            .sid;
        let h = n.header("POST", "/api/publish", b"", now);
        assert_eq!(
            ws.precheck(&h, None, Scope::Transfer).unwrap_err().code,
            "scope_required"
        );
        let h = n.header("GET", "/api/status", b"", now);
        assert!(ws.precheck(&h, None, Scope::Status).is_ok());
    }

    #[test]
    fn idle_timeout_and_maximum_lifetime() {
        let (ws, clock) = sessions();
        // Idle: unused for just over 15 minutes.
        let c = open(&ws, &clock);
        clock.advance(Duration::from_secs(14 * 60));
        let h = c.header("GET", "/api/status", b"", clock.unix_ms());
        assert!(ws.verify(&h, "GET", "/api/status", b"").is_ok());
        clock.advance(Duration::from_secs(14 * 60));
        let h = c.header("GET", "/api/status", b"", clock.unix_ms());
        assert!(
            ws.verify(&h, "GET", "/api/status", b"").is_ok(),
            "use extends idle"
        );
        clock.advance(Duration::from_secs(15 * 60 + 1));
        let h = c.header("GET", "/api/status", b"", clock.unix_ms());
        assert_eq!(
            ws.precheck(&h, None, Scope::Status).unwrap_err().code,
            "session_expired"
        );
        assert_eq!(ws.counts().0, 0);

        // Maximum lifetime: kept busy, still ends at 12 hours.
        let c = open(&ws, &clock);
        let created_ms = clock.elapsed_ms.load(Ordering::SeqCst);
        let twelve_hours_ms = 12 * 3600 * 1000;
        let mut ended = false;
        for _ in 0..100 {
            clock.advance(Duration::from_secs(14 * 60));
            let age_ms = clock.elapsed_ms.load(Ordering::SeqCst) - created_ms;
            let h = c.header("GET", "/api/status", b"", clock.unix_ms());
            match ws.verify(&h, "GET", "/api/status", b"") {
                Ok(_) => assert!(age_ms <= twelve_hours_ms, "still valid at age {age_ms} ms"),
                Err(e) => {
                    assert_eq!(e.code, "session_expired");
                    assert!(age_ms > twelve_hours_ms, "ended early at age {age_ms} ms");
                    ended = true;
                    break;
                }
            }
        }
        assert!(ended);
    }

    #[test]
    fn table_sizes_are_bounded() {
        let (ws, clock) = sessions();
        // Outstanding boot values: the oldest is replaced.
        let mut boots = Vec::new();
        for _ in 0..6 {
            boots.push(ws.issue_boot(ORIGIN, &[]).unwrap().0);
        }
        assert_eq!(ws.counts().1, 4);
        let c = Client::new();
        assert_eq!(
            ws.register(Some(ORIGIN), &c.register_body(&boots[0], clock.unix_ms()))
                .unwrap_err()
                .code,
            "boot_invalid"
        );
        // Sessions: the ninth is refused, an open one is kept.
        let (ws, clock) = sessions();
        let first = open(&ws, &clock);
        for _ in 0..7 {
            open(&ws, &clock);
        }
        assert_eq!(ws.counts().0, 8);
        let (boot, _) = ws.issue_boot(ORIGIN, &[]).unwrap();
        let e = ws
            .register(
                Some(ORIGIN),
                &Client::new().register_body(&boot, clock.unix_ms()),
            )
            .unwrap_err();
        assert_eq!((e.status, e.code), (429, "too_many_sessions"));
        let h = first.header("GET", "/api/status", b"", clock.unix_ms());
        assert!(ws.verify(&h, "GET", "/api/status", b"").is_ok());
        // Used boot values are remembered only up to a cap.
        let clock = FakeClock::new();
        let limits = Limits {
            max_sessions: 100,
            ..Limits::default()
        };
        let ws = WebSessions::with_limits_and_clock(limits, clock.clone());
        for _ in 0..20 {
            open(&ws, &clock);
        }
        assert_eq!(ws.lock().consumed.len(), 16);
    }

    #[test]
    fn repeated_bad_signatures_end_the_session() {
        let (ws, clock) = sessions();
        let c = open(&ws, &clock);
        let now = clock.unix_ms();
        for i in 0..10 {
            let mut h = c.header("GET", "/api/status", b"", now);
            h.signature[0] ^= 1;
            let e = ws.verify(&h, "GET", "/api/status", b"").unwrap_err();
            assert_eq!(e.code, "bad_signature", "{i}");
        }
        let h = c.header("GET", "/api/status", b"", now);
        assert_eq!(
            ws.verify(&h, "GET", "/api/status", b"").unwrap_err().code,
            "session_unknown"
        );
    }

    #[test]
    fn a_good_request_resets_the_failure_count() {
        let (ws, clock) = sessions();
        let c = open(&ws, &clock);
        let now = clock.unix_ms();
        for _ in 0..9 {
            let mut h = c.header("GET", "/api/status", b"", now);
            h.signature[0] ^= 1;
            let _ = ws.verify(&h, "GET", "/api/status", b"");
        }
        let h = c.header("GET", "/api/status", b"", now);
        assert!(ws.verify(&h, "GET", "/api/status", b"").is_ok());
        for _ in 0..9 {
            let mut h = c.header("GET", "/api/status", b"", now);
            h.signature[0] ^= 1;
            let _ = ws.verify(&h, "GET", "/api/status", b"");
        }
        let h = c.header("GET", "/api/status", b"", now);
        assert!(ws.verify(&h, "GET", "/api/status", b"").is_ok());
    }

    #[test]
    fn revoking_ends_sessions() {
        let (ws, clock) = sessions();
        let a = open(&ws, &clock);
        let _b = open(&ws, &clock);
        assert_eq!(ws.list().len(), 2);
        assert_eq!(ws.revoke(Some("x")), 0, "a short prefix matches nothing");
        assert_eq!(ws.revoke(Some(&a.sid[..4])), 1);
        assert_eq!(ws.counts().0, 1);
        let _ = ws.issue_boot(ORIGIN, &[]).unwrap();
        assert_eq!(ws.revoke(None), 1);
        assert_eq!(ws.counts(), (0, 0));
        let sid: [u8; 16] = dec(&a.sid).unwrap();
        assert!(!ws.end(&sid));
    }

    #[test]
    fn header_syntax_is_strict() {
        let sid = B64U.encode([1u8; 16]);
        let n = B64U.encode([2u8; 16]);
        let sig = B64U.encode([3u8; 64]);
        let ok = format!("MiasmaSig v=1, sid={sid}, ts=1800000000000, n={n}, sig={sig}");
        let h = SigHeader::parse(&ok).unwrap();
        assert_eq!(
            (h.ts, h.sid, h.nonce),
            (1_800_000_000_000, [1; 16], [2; 16])
        );
        for bad in [
            format!("Bearer v=1, sid={sid}, ts=1, n={n}, sig={sig}"),
            format!("MiasmaSig v=2, sid={sid}, ts=1, n={n}, sig={sig}"),
            format!("MiasmaSig v=1,sid={sid}, ts=1, n={n}, sig={sig}"),
            format!("MiasmaSig v=1, ts=1, sid={sid}, n={n}, sig={sig}"),
            format!("MiasmaSig v=1, sid={sid}, ts=-1, n={n}, sig={sig}"),
            format!("MiasmaSig v=1, sid={sid}, ts=, n={n}, sig={sig}"),
            format!("MiasmaSig v=1, sid={sid}, ts=1, n={n}, sig={sig}, x=1"),
            format!("MiasmaSig v=1, sid={sid}=, ts=1, n={n}, sig={sig}"),
            format!(
                "MiasmaSig v=1, sid={}, ts=1, n={n}, sig={sig}",
                B64U.encode([1u8; 15])
            ),
            format!(
                "MiasmaSig v=1, sid={sid}, ts=1, n={n}, sig={}",
                "A".repeat(200)
            ),
            String::from("MiasmaSig"),
        ] {
            assert_eq!(
                SigHeader::parse(&bad).unwrap_err().code,
                "bad_auth_header",
                "{bad}"
            );
        }
    }

    #[test]
    fn canonical_strings_have_the_documented_shape() {
        let s = canonical_request(
            "POST",
            "/api/publish?a=%2F",
            ORIGIN,
            "SID",
            5,
            "NON",
            b"abc",
        );
        assert_eq!(
            s,
            format!(
                "miasma-web-sig-v1\nPOST\n/api/publish?a=%2F\n{ORIGIN}\nSID\n5\nNON\n{}",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            )
        );
        assert_eq!(
            register_message(ORIGIN, "B", "P", 7),
            format!("miasma-web-register-v1\n{ORIGIN}\nB\nP\n7")
        );
        // The empty body hashes to the SHA-256 of nothing.
        assert_eq!(
            body_hash_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn every_listed_route_has_the_expected_scope() {
        use Scope::*;
        let table: &[(&str, &str, Option<Scope>)] = &[
            ("GET", "/api/status", Some(Status)),
            ("GET", "/api/sharing-key", Some(Status)),
            ("GET", "/api/session", Some(Status)),
            ("POST", "/api/session/end", Some(Status)),
            ("GET", "/api/transfers", Some(Status)),
            ("GET", "/api/transfers/abc", Some(Status)),
            ("POST", "/api/publish", Some(Transfer)),
            ("POST", "/api/retrieve", Some(Transfer)),
            ("POST", "/api/transfers/receive", Some(Transfer)),
            ("POST", "/api/transfers/abc/cancel", Some(Transfer)),
            ("POST", "/api/transfers/abc/remove", Some(Transfer)),
            ("POST", "/api/transfers/clear-finished", Some(Transfer)),
            ("POST", "/api/directed/send", Some(Directed)),
            ("POST", "/api/directed/confirm", Some(Directed)),
            ("POST", "/api/directed/retrieve", Some(Directed)),
            ("POST", "/api/directed/revoke", Some(Directed)),
            ("GET", "/api/directed/inbox", Some(Directed)),
            ("GET", "/api/directed/outbox", Some(Directed)),
            ("POST", "/api/wipe", Some(Destructive)),
            // Host paths and everything unknown: no session may call them.
            ("POST", "/api/publish-file", None),
            ("POST", "/api/retrieve-to-file", None),
            ("POST", "/api/directed/send-file", None),
            ("POST", "/api/directed/retrieve-to-file", None),
            ("GET", "/api/anything-new", None),
            ("POST", "/api/transfers", None),
            ("GET", "/api/transfersx", None),
            ("DELETE", "/api/status", None),
            ("GET", "/api/publish", None),
        ];
        for (m, p, want) in table {
            assert_eq!(required_scope(m, p), *want, "{m} {p}");
        }
    }

    /// Every route the bridge matches on is either given a scope or listed
    /// here as deliberately outside the session scopes.
    #[test]
    fn every_route_in_the_bridge_source_is_accounted_for() {
        const OUTSIDE: &[&str] = &[
            "/api/ping",
            "/api/session/register",
            "/api/publish-file",
            "/api/retrieve-to-file",
            "/api/directed/send-file",
            "/api/directed/retrieve-to-file",
        ];
        let src = include_str!("http_bridge.rs");
        let mut seen = 0;
        for line in src.lines() {
            let t = line.trim_start();
            let Some(rest) = t.strip_prefix("(Method::") else {
                continue;
            };
            let Some((method, rest)) = rest.split_once(", \"") else {
                continue;
            };
            let Some((path, _)) = rest.split_once('"') else {
                continue;
            };
            if !path.starts_with("/api/") {
                continue;
            }
            seen += 1;
            let m = method.to_ascii_uppercase();
            assert!(
                required_scope(&m, path).is_some() || OUTSIDE.contains(&path),
                "{m} {path} has no session scope; add it to required_scope or to this list"
            );
        }
        assert!(seen >= 10, "the scan found only {seen} routes");
    }
}
