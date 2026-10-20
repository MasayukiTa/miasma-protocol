//! Hybrid key exchange: X25519 + ML-KEM-768 (FIPS 203).
//!
//! Compiled only with the `pqc` cargo feature. The one live user is the
//! opt-in upgrade of private-conversation sessions (`chat::pq`, off unless
//! `privacy.pqc_mode` is `prefer` or `require`); see
//! `docs/pqc-session-upgrade.md`. That wiring has not been reviewed by an
//! outside cryptographer.
//!
//! # Shape
//!
//! Both sides already know each other's [`Capabilities`] (exchanged and
//! negotiated with `protocol::capability` before the key exchange). Then:
//!
//! ```text
//! initiator                                         responder
//!   msg1: X25519 public [+ ML-KEM encapsulation key]  ->
//!                                                   <-  msg2: X25519 public [+ ML-KEM ciphertext]
//! ```
//!
//! Each side derives the same session key and two key-confirmation tags.
//! A caller proves the transcript matched by exchanging the tags
//! ([`Established::confirmation`] / [`Established::verify_peer_confirmation`]).
//!
//! # Key derivation
//!
//! The two shared secrets are never combined by XOR. They are length-prefixed
//! and concatenated as the input keying material of HKDF-SHA256. The salt is a
//! SHA-256 hash of the whole transcript, and every output has its own
//! domain-separated `info` label:
//!
//! * the exchange version and the suite,
//! * the T1 capability `transcript_binding` digest (both offers and the
//!   agreed result),
//! * the endpoint identities of both roles,
//! * both X25519 public values, the ML-KEM encapsulation key and the
//!   ML-KEM ciphertext, each tagged with the role that produced it.
//!
//! # Downgrade handling
//!
//! * [`Mode::Strict`]: the local side demands the hybrid suite. If the agreed
//!   set lacks it, setup fails with [`HybridError::Negotiation`]. This is the
//!   local side's own demand only; a peer's policy is never evaluated here.
//! * [`Mode::Compatibility`]: when the peer lacks the hybrid suite the
//!   exchange runs classical-only and [`Established::downgraded`] is `true`,
//!   with the reasons in [`Established::downgrade_reasons`], so a UI can show
//!   it.
//! * If the capability view of the two sides differs (an on-path edit of an
//!   offer), either the suite check fails at once or the transcripts differ
//!   and the confirmation tags do not match. A message that drops the
//!   ML-KEM part when the agreed suite is hybrid is rejected in both modes.
//!
//! # Fragmentation
//!
//! The ML-KEM encapsulation key (1184 bytes) and ciphertext (1088 bytes) make
//! each message larger than a typical handshake frame. [`fragment_message`]
//! and [`MessageReassembler`] wrap `protocol::fragment`; use them only when
//! `FEATURE_FRAGMENTATION` was agreed.
//!
//! # Wire format (big-endian)
//!
//! ```text
//! tag       u8     1 = initiator message, 2 = responder message
//! version   u8     must be KEX_VERSION
//! suite     u16    SUITE_ID_CLASSICAL or SUITE_ID_HYBRID
//! x25519    32 bytes
//! kem_len   u16    0 (classical) or exactly 1184 / 1088 (hybrid)
//! kem       kem_len bytes
//! ```
//!
//! Nothing may follow. Any other value fails closed.
//!
//! # Memory hygiene
//!
//! Secrets live in `Zeroizing` / zeroize-on-drop types (the X25519 secret,
//! the ML-KEM decapsulation key, both shared secrets, the combined input and
//! the session key). A Rust move copies bytes, so values are only as clean as
//! the code that handled the earlier copy; nothing here is `Clone`.

use std::collections::{HashSet, VecDeque};
use std::convert::Infallible;

use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    DecapsulationKey768, EncapsulationKey768, Generate, Key, KeyExport,
};
use rand::{CryptoRng, RngCore};
use rand_core_pqc::{TryCryptoRng, TryRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use super::capability::{
    negotiate_reported, transcript_binding, Agreed, Capabilities, DowngradeReason, DowngradeReport,
    NegotiationError, Requirements, SUITE_CLASSICAL, SUITE_HYBRID_X25519_MLKEM768,
};
use super::fragment::{
    fragment, FragmentError, HandshakeFragment, PushOutcome, Reassembler, ReassemblyLimits,
};

/// Version of this key exchange's message and transcript layout.
pub const KEX_VERSION: u8 = 1;
/// Suite id carried in messages and in fragment headers: classical X25519.
pub const SUITE_ID_CLASSICAL: u16 = 1;
/// Suite id carried in messages and in fragment headers: X25519 + ML-KEM-768.
pub const SUITE_ID_HYBRID: u16 = 2;

/// ML-KEM-768 encapsulation key length.
pub const EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length.
pub const CT_LEN: usize = 1088;

const TAG_INITIATOR: u8 = 1;
const TAG_RESPONDER: u8 = 2;
const HEADER_LEN: usize = 1 + 1 + 2 + 32 + 2;

/// Largest message this module produces or accepts.
pub const MAX_MESSAGE_LEN: usize = HEADER_LEN + EK_LEN;

const L_TRANSCRIPT: &[u8] = b"miasma hybrid kex transcript v1";
const L_SESSION: &[u8] = b"miasma hybrid kex v1 session key";
const L_CONFIRM_I: &[u8] = b"miasma hybrid kex v1 confirm initiator";
const L_CONFIRM_R: &[u8] = b"miasma hybrid kex v1 confirm responder";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HybridError {
    #[error("negotiation failed: {0}")]
    Negotiation(#[from] NegotiationError),
    #[error("message truncated")]
    Truncated,
    #[error("unexpected trailing bytes")]
    TrailingBytes,
    #[error("unexpected message tag {0}")]
    BadTag(u8),
    #[error("unsupported exchange version {0}")]
    BadVersion(u8),
    #[error("message suite does not match the agreed suite")]
    SuiteMismatch,
    #[error("post-quantum part has an invalid length")]
    BadKemLength,
    #[error("the agreed suite is hybrid but the message has no post-quantum part")]
    HybridStripped,
    #[error("invalid ML-KEM encapsulation key")]
    InvalidKemKey,
    #[error("X25519 value is not contributory")]
    NonContributory,
    #[error("replayed first message")]
    Replay,
    #[error("key confirmation does not match")]
    ConfirmMismatch,
    #[error("fragment: {0}")]
    Fragment(#[from] FragmentError),
}

/// Local policy for the exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Fail unless the hybrid suite is agreed.
    Strict,
    /// Use the hybrid suite when both sides have it, otherwise classical-only
    /// with a visible downgraded flag.
    Compatibility,
}

/// The suite that was actually used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    ClassicalOnly,
    Hybrid,
}

/// Everything both roles need to agree on before the exchange.
#[derive(Debug, Clone)]
pub struct Config {
    pub mode: Mode,
    /// The local side's capabilities, as it sent them.
    pub local: Capabilities,
    /// The peer's capabilities, as received.
    pub remote: Capabilities,
    /// Endpoint identity of the initiator (for example its public key).
    pub initiator_id: Vec<u8>,
    /// Endpoint identity of the responder.
    pub responder_id: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

struct Plan {
    agreed: Agreed,
    suite: Suite,
    binding: [u8; 32],
}

impl Plan {
    fn suite_id(&self) -> u16 {
        match self.suite {
            Suite::Hybrid => SUITE_ID_HYBRID,
            Suite::ClassicalOnly => SUITE_ID_CLASSICAL,
        }
    }
}

fn plan(cfg: &Config, role: Role) -> Result<Plan, HybridError> {
    let require = Requirements {
        suites: match cfg.mode {
            Mode::Strict => SUITE_HYBRID_X25519_MLKEM768,
            Mode::Compatibility => 0,
        },
        features: 0,
    };
    // Reported, so the downgrade is counted in the daemon status as well.
    let negotiation = negotiate_reported(&cfg.local, &cfg.remote, &require)?;
    debug_assert_eq!(
        negotiation.report.is_downgrade(),
        negotiation.agreed.downgraded
    );
    let agreed = negotiation.agreed;
    let (init, resp) = match role {
        Role::Initiator => (&cfg.local, &cfg.remote),
        Role::Responder => (&cfg.remote, &cfg.local),
    };
    let binding = transcript_binding(init, resp, &agreed);
    let suite = if agreed.has_suite(SUITE_HYBRID_X25519_MLKEM768) {
        Suite::Hybrid
    } else {
        debug_assert!(agreed.has_suite(SUITE_CLASSICAL));
        Suite::ClassicalOnly
    };
    Ok(Plan {
        agreed,
        suite,
        binding,
    })
}

// ---------------------------------------------------------------------------
// Secret container

/// A 32-byte secret that is wiped when dropped.
struct Secret32([u8; 32]);

#[cfg(test)]
thread_local! {
    static SECRET_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        {
            assert!(self.0.iter().all(|b| *b == 0));
            SECRET_DROPS.with(|c| c.set(c.get() + 1));
        }
    }
}

impl Secret32 {
    fn from_slice(src: &[u8]) -> Self {
        let mut s = Secret32([0u8; 32]);
        s.0.copy_from_slice(src);
        s
    }
}

// ---------------------------------------------------------------------------
// RNG adapter: the existing random source (rand 0.8) for the ML-KEM crate's
// RNG traits.

struct KemRng<'a, R: RngCore + CryptoRng>(&'a mut R);

impl<R: RngCore + CryptoRng> TryRng for KemRng<'_, R> {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.0.next_u32())
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.0.next_u64())
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

impl<R: RngCore + CryptoRng> TryCryptoRng for KemRng<'_, R> {}

// ---------------------------------------------------------------------------
// Messages

struct Parsed<'a> {
    x25519: [u8; 32],
    kem: &'a [u8],
}

fn encode_msg(tag: u8, suite_id: u16, x25519: &[u8; 32], kem: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + kem.len());
    out.push(tag);
    out.push(KEX_VERSION);
    out.extend_from_slice(&suite_id.to_be_bytes());
    out.extend_from_slice(x25519);
    out.extend_from_slice(&(kem.len() as u16).to_be_bytes());
    out.extend_from_slice(kem);
    out
}

/// Parse and validate against the plan. Every length is checked before use.
fn parse_msg<'a>(buf: &'a [u8], tag: u8, plan: &Plan) -> Result<Parsed<'a>, HybridError> {
    if buf.len() < HEADER_LEN {
        return Err(HybridError::Truncated);
    }
    if buf[0] != tag {
        return Err(HybridError::BadTag(buf[0]));
    }
    if buf[1] != KEX_VERSION {
        return Err(HybridError::BadVersion(buf[1]));
    }
    let suite_id = u16::from_be_bytes([buf[2], buf[3]]);
    if suite_id != plan.suite_id() {
        return Err(HybridError::SuiteMismatch);
    }
    let mut x25519 = [0u8; 32];
    x25519.copy_from_slice(&buf[4..36]);
    let kem_len = u16::from_be_bytes([buf[36], buf[37]]) as usize;
    let want = match (plan.suite, tag) {
        (Suite::ClassicalOnly, _) => 0,
        (Suite::Hybrid, TAG_INITIATOR) => EK_LEN,
        (Suite::Hybrid, _) => CT_LEN,
    };
    let body = &buf[HEADER_LEN..];
    if kem_len == 0 && want != 0 {
        return Err(HybridError::HybridStripped);
    }
    if kem_len != want {
        return Err(HybridError::BadKemLength);
    }
    if body.len() < kem_len {
        return Err(HybridError::Truncated);
    }
    if body.len() > kem_len {
        return Err(HybridError::TrailingBytes);
    }
    Ok(Parsed { x25519, kem: body })
}

// ---------------------------------------------------------------------------
// Derivation

fn put_lp(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u32).to_be_bytes());
    h.update(bytes);
}

struct Transcript<'a> {
    plan: &'a Plan,
    cfg: &'a Config,
    x_init: &'a [u8; 32],
    ek: &'a [u8],
    x_resp: &'a [u8; 32],
    ct: &'a [u8],
}

impl Transcript<'_> {
    fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        put_lp(&mut h, L_TRANSCRIPT);
        h.update([KEX_VERSION]);
        h.update(self.plan.suite_id().to_be_bytes());
        put_lp(&mut h, &self.plan.binding);
        put_lp(&mut h, b"initiator id");
        put_lp(&mut h, &self.cfg.initiator_id);
        put_lp(&mut h, b"responder id");
        put_lp(&mut h, &self.cfg.responder_id);
        put_lp(&mut h, b"initiator x25519");
        put_lp(&mut h, self.x_init);
        put_lp(&mut h, b"initiator mlkem encapsulation key");
        put_lp(&mut h, self.ek);
        put_lp(&mut h, b"responder x25519");
        put_lp(&mut h, self.x_resp);
        put_lp(&mut h, b"responder mlkem ciphertext");
        put_lp(&mut h, self.ct);
        h.finalize().into()
    }
}

/// Result of a completed exchange.
pub struct Established {
    key: Secret32,
    confirm_initiator: [u8; 32],
    confirm_responder: [u8; 32],
    role: Role,
    suite: Suite,
    agreed: Agreed,
}

impl std::fmt::Debug for Established {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Established")
            .field("suite", &self.suite)
            .field("downgraded", &self.agreed.downgraded)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Established {
    /// The derived 32-byte session key.
    pub fn session_key(&self) -> &[u8; 32] {
        &self.key.0
    }

    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// The negotiated capability result (features such as fragmentation).
    pub fn agreed(&self) -> &Agreed {
        &self.agreed
    }

    /// True when the exchange runs below what the local side offered. Show it.
    pub fn downgraded(&self) -> bool {
        self.agreed.downgraded
    }

    pub fn downgrade_reasons(&self) -> &[DowngradeReason] {
        &self.agreed.reasons
    }

    /// The downgrade report for this exchange. Read it and show it.
    pub fn downgrade_report(&self) -> DowngradeReport {
        DowngradeReport::from_agreed(&self.agreed)
    }

    /// The tag this side sends to prove it derived the same keys.
    pub fn confirmation(&self) -> [u8; 32] {
        match self.role {
            Role::Initiator => self.confirm_initiator,
            Role::Responder => self.confirm_responder,
        }
    }

    /// The tag this side expects from the peer. A caller that has to keep the
    /// exchange across a restart stores it next to the session key and
    /// compares in constant time later; it is derived from the same transcript
    /// as the key.
    pub fn expected_peer_confirmation(&self) -> [u8; 32] {
        match self.role {
            Role::Initiator => self.confirm_responder,
            Role::Responder => self.confirm_initiator,
        }
    }

    /// Check the tag received from the peer, in constant time. A mismatch
    /// means the transcripts differ (tampering or a downgrade attempt).
    pub fn verify_peer_confirmation(&self, tag: &[u8; 32]) -> Result<(), HybridError> {
        let expected = match self.role {
            Role::Initiator => &self.confirm_responder,
            Role::Responder => &self.confirm_initiator,
        };
        if bool::from(expected.ct_eq(tag)) {
            Ok(())
        } else {
            Err(HybridError::ConfirmMismatch)
        }
    }
}

fn derive(
    t: &Transcript<'_>,
    role: Role,
    ss_x: &Secret32,
    ss_k: Option<&Secret32>,
) -> Result<Established, HybridError> {
    let salt = t.hash();
    let mut ikm = Zeroizing::new(Vec::with_capacity(4 + 32 + 4 + 32));
    ikm.extend_from_slice(&32u32.to_be_bytes());
    ikm.extend_from_slice(&ss_x.0);
    match ss_k {
        Some(k) => {
            ikm.extend_from_slice(&32u32.to_be_bytes());
            ikm.extend_from_slice(&k.0);
        }
        None => ikm.extend_from_slice(&0u32.to_be_bytes()),
    }
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut key = Secret32([0u8; 32]);
    hk.expand(L_SESSION, &mut key.0)
        .map_err(|_| HybridError::Truncated)?;
    let mut ci = [0u8; 32];
    let mut cr = [0u8; 32];
    hk.expand(L_CONFIRM_I, &mut ci)
        .map_err(|_| HybridError::Truncated)?;
    hk.expand(L_CONFIRM_R, &mut cr)
        .map_err(|_| HybridError::Truncated)?;
    Ok(Established {
        key,
        confirm_initiator: ci,
        confirm_responder: cr,
        role,
        suite: t.plan.suite,
        agreed: t.plan.agreed.clone(),
    })
}

fn dh(secret: &StaticSecret, peer: &[u8; 32]) -> Result<Secret32, HybridError> {
    let shared = secret.diffie_hellman(&PublicKey::from(*peer));
    if !shared.was_contributory() {
        return Err(HybridError::NonContributory);
    }
    Ok(Secret32(shared.to_bytes()))
}

// ---------------------------------------------------------------------------
// Initiator

pub struct Initiator {
    cfg: Config,
    plan: Plan,
    x_secret: StaticSecret,
    x_public: [u8; 32],
    dk: Option<DecapsulationKey768>,
    ek_bytes: Vec<u8>,
}

impl Initiator {
    /// Build the first message. Fails now (before sending anything) if a
    /// strict local policy cannot be met.
    pub fn start<R: RngCore + CryptoRng>(
        cfg: Config,
        rng: &mut R,
    ) -> Result<(Self, Vec<u8>), HybridError> {
        let plan = plan(&cfg, Role::Initiator)?;
        let x_secret = StaticSecret::random_from_rng(&mut *rng);
        let x_public = PublicKey::from(&x_secret).to_bytes();
        let (dk, ek_bytes) = match plan.suite {
            Suite::Hybrid => {
                let dk = DecapsulationKey768::generate_from_rng(&mut KemRng(rng));
                let ek = dk.encapsulation_key().to_bytes().to_vec();
                (Some(dk), ek)
            }
            Suite::ClassicalOnly => (None, Vec::new()),
        };
        let msg = encode_msg(TAG_INITIATOR, plan.suite_id(), &x_public, &ek_bytes);
        Ok((
            Self {
                cfg,
                plan,
                x_secret,
                x_public,
                dk,
                ek_bytes,
            },
            msg,
        ))
    }

    /// The suite id of the first message (also the fragment header suite).
    pub fn suite_id(&self) -> u16 {
        self.plan.suite_id()
    }

    /// Process the responder's message.
    pub fn finish(self, msg2: &[u8]) -> Result<Established, HybridError> {
        let parsed = parse_msg(msg2, TAG_RESPONDER, &self.plan)?;
        let ss_x = dh(&self.x_secret, &parsed.x25519)?;
        let ss_k = match &self.dk {
            Some(dk) => {
                let ct = ml_kem::Ciphertext::<ml_kem::MlKem768>::try_from(parsed.kem)
                    .map_err(|_| HybridError::BadKemLength)?;
                // ML-KEM decapsulation never fails: a tampered ciphertext
                // yields an unrelated key (implicit rejection), and the
                // confirmation tags then expose the mismatch.
                let mut k = dk.decapsulate(&ct);
                let s = Secret32::from_slice(&k);
                k.as_mut_slice().zeroize();
                Some(s)
            }
            None => None,
        };
        let t = Transcript {
            plan: &self.plan,
            cfg: &self.cfg,
            x_init: &self.x_public,
            ek: &self.ek_bytes,
            x_resp: &parsed.x25519,
            ct: parsed.kem,
        };
        derive(&t, Role::Initiator, &ss_x, ss_k.as_ref())
    }
}

// ---------------------------------------------------------------------------
// Responder

/// Remembers recent first messages so a replayed one is refused. Bounded.
pub struct ReplayGuard {
    capacity: usize,
    order: VecDeque<[u8; 32]>,
    seen: HashSet<[u8; 32]>,
}

impl ReplayGuard {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            seen: HashSet::new(),
        }
    }

    fn contains(&self, id: &[u8; 32]) -> bool {
        self.seen.contains(id)
    }

    fn insert(&mut self, id: [u8; 32]) {
        if self.seen.insert(id) {
            self.order.push_back(id);
            while self.order.len() > self.capacity {
                if let Some(old) = self.order.pop_front() {
                    self.seen.remove(&old);
                }
            }
        }
    }
}

pub struct Responder;

impl Responder {
    /// Process the initiator's first message and produce the reply.
    pub fn accept<R: RngCore + CryptoRng>(
        cfg: Config,
        msg1: &[u8],
        guard: &mut ReplayGuard,
        rng: &mut R,
    ) -> Result<(Established, Vec<u8>), HybridError> {
        let plan = plan(&cfg, Role::Responder)?;
        let parsed = parse_msg(msg1, TAG_INITIATOR, &plan)?;
        let replay_id: [u8; 32] = Sha256::digest(msg1).into();
        if guard.contains(&replay_id) {
            return Err(HybridError::Replay);
        }

        let x_secret = StaticSecret::random_from_rng(&mut *rng);
        let x_public = PublicKey::from(&x_secret).to_bytes();
        let ss_x = dh(&x_secret, &parsed.x25519)?;
        let (ss_k, ct_bytes) = match plan.suite {
            Suite::Hybrid => {
                let key = Key::<EncapsulationKey768>::try_from(parsed.kem)
                    .map_err(|_| HybridError::BadKemLength)?;
                let ek = EncapsulationKey768::new(&key).map_err(|_| HybridError::InvalidKemKey)?;
                let (ct, mut k) = ek.encapsulate_with_rng(&mut KemRng(rng));
                let s = Secret32::from_slice(&k);
                k.as_mut_slice().zeroize();
                (Some(s), ct.to_vec())
            }
            Suite::ClassicalOnly => (None, Vec::new()),
        };
        let msg2 = encode_msg(TAG_RESPONDER, plan.suite_id(), &x_public, &ct_bytes);
        let t = Transcript {
            plan: &plan,
            cfg: &cfg,
            x_init: &parsed.x25519,
            ek: parsed.kem,
            x_resp: &x_public,
            ct: &ct_bytes,
        };
        let est = derive(&t, Role::Responder, &ss_x, ss_k.as_ref())?;
        guard.insert(replay_id);
        Ok((est, msg2))
    }
}

// ---------------------------------------------------------------------------
// Fragmentation helpers

/// Split an exchange message into encoded fragment frames.
pub fn fragment_message(
    handshake_id: u64,
    suite_id: u16,
    msg: &[u8],
    max_payload: usize,
) -> Result<Vec<Vec<u8>>, HybridError> {
    Ok(fragment(handshake_id, suite_id, msg, max_payload)?
        .iter()
        .map(HandshakeFragment::encode)
        .collect())
}

/// A reassembled message with the id and suite taken from the fragments.
#[derive(Debug, PartialEq, Eq)]
pub struct Assembled {
    pub handshake_id: u64,
    pub suite_id: u16,
    pub data: Vec<u8>,
}

/// Bounded reassembly of exchange messages (see `protocol::fragment`).
pub struct MessageReassembler {
    inner: Reassembler,
}

impl MessageReassembler {
    pub fn new() -> Self {
        Self::with_limits(ReassemblyLimits {
            max_total_len: MAX_MESSAGE_LEN as u32,
            max_fragments: 64,
            max_concurrent: 8,
            timeout_ms: 10_000,
        })
    }

    pub fn with_limits(mut limits: ReassemblyLimits) -> Self {
        limits.max_total_len = limits.max_total_len.min(MAX_MESSAGE_LEN as u32);
        Self {
            inner: Reassembler::new(limits),
        }
    }

    pub fn in_progress(&self) -> usize {
        self.inner.in_progress()
    }

    pub fn expire(&mut self, now_ms: u64) -> usize {
        self.inner.expire(now_ms)
    }

    /// Feed one encoded frame. Returns the message once all fragments are in.
    /// The suite in the fragment header must equal the suite inside the
    /// message, or the message is refused.
    pub fn push_frame(
        &mut self,
        frame: &[u8],
        now_ms: u64,
    ) -> Result<Option<Assembled>, HybridError> {
        let frag = HandshakeFragment::decode(frame)?;
        match self.inner.push(frag, now_ms)? {
            PushOutcome::Pending | PushOutcome::Duplicate => Ok(None),
            PushOutcome::Complete {
                handshake_id,
                suite,
                data,
            } => {
                if data.len() < 4 || u16::from_be_bytes([data[2], data[3]]) != suite {
                    return Err(HybridError::SuiteMismatch);
                }
                Ok(Some(Assembled {
                    handshake_id,
                    suite_id: suite,
                    data,
                }))
            }
        }
    }
}

impl Default for MessageReassembler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::seq::SliceRandom;
    use rand::SeedableRng;

    fn caps_hybrid() -> Capabilities {
        Capabilities::current()
    }

    fn cfg(mode: Mode, local: Capabilities, remote: Capabilities) -> Config {
        Config {
            mode,
            local,
            remote,
            initiator_id: b"initiator-endpoint".to_vec(),
            responder_id: b"responder-endpoint".to_vec(),
        }
    }

    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    /// Run a full exchange; returns both results and both messages.
    fn run(
        ci: Config,
        cr: Config,
    ) -> Result<(Established, Established, Vec<u8>, Vec<u8>), HybridError> {
        let mut g = ReplayGuard::new(16);
        let (init, m1) = Initiator::start(ci, &mut rng(1))?;
        let (er, m2) = Responder::accept(cr, &m1, &mut g, &mut rng(2))?;
        let ei = init.finish(&m2)?;
        Ok((ei, er, m1, m2))
    }

    fn pair(
        mode_i: Mode,
        caps_i: Capabilities,
        mode_r: Mode,
        caps_r: Capabilities,
    ) -> (Config, Config) {
        (
            cfg(mode_i, caps_i.clone(), caps_r.clone()),
            cfg(mode_r, caps_r, caps_i),
        )
    }

    fn confirmed(a: &Established, b: &Established) -> bool {
        a.verify_peer_confirmation(&b.confirmation()).is_ok()
            && b.verify_peer_confirmation(&a.confirmation()).is_ok()
    }

    // --- known answers -----------------------------------------------------

    fn sha256_hex(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    /// Public example key from the crate's own PKCS#8 test material: the
    /// 64-byte seed 00 01 02 .. 3f must give this ML-KEM-768 encapsulation
    /// key (hash of its 1184 bytes). Independent of this module's code.
    #[test]
    fn kat_seed_to_encapsulation_key() {
        let seed_bytes: Vec<u8> = (0u8..64).collect();
        let seed = ml_kem::Seed::try_from(&seed_bytes[..]).unwrap();
        let dk = DecapsulationKey768::from_seed(seed);
        let ek = dk.encapsulation_key().to_bytes();
        assert_eq!(ek.len(), EK_LEN);
        assert_eq!(&ek[..4], &hex::decode("298aa10d").unwrap()[..]);
        assert_eq!(
            sha256_hex(&ek),
            "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9"
        );
    }

    #[test]
    fn kem_sizes_match_fips203() {
        let dk = DecapsulationKey768::generate_from_rng(&mut KemRng(&mut rng(7)));
        let ek = dk.encapsulation_key();
        let (ct, k1) = ek.encapsulate_with_rng(&mut KemRng(&mut rng(8)));
        assert_eq!(ek.to_bytes().len(), EK_LEN);
        assert_eq!(ct.len(), CT_LEN);
        assert_eq!(k1.len(), 32);
        assert_eq!(dk.decapsulate(&ct), k1);
    }

    #[test]
    fn kem_implicit_rejection_gives_unrelated_key() {
        let dk = DecapsulationKey768::generate_from_rng(&mut KemRng(&mut rng(7)));
        let (ct, k) = dk
            .encapsulation_key()
            .encapsulate_with_rng(&mut KemRng(&mut rng(8)));
        let mut bad = ct;
        bad[10] ^= 1;
        let k_bad = dk.decapsulate(&bad);
        assert_ne!(k, k_bad);
        // Deterministic: same bad ciphertext, same rejection key.
        assert_eq!(k_bad, dk.decapsulate(&bad));
        // Another key pair gives yet another value.
        let other = DecapsulationKey768::generate_from_rng(&mut KemRng(&mut rng(9)));
        assert_ne!(other.decapsulate(&ct), k);
    }

    // --- round trip --------------------------------------------------------

    #[test]
    fn hybrid_round_trip_and_sizes() {
        for mode in [Mode::Strict, Mode::Compatibility] {
            let (ci, cr) = pair(mode, caps_hybrid(), mode, caps_hybrid());
            let (ei, er, m1, m2) = run(ci, cr).unwrap();
            assert_eq!(ei.session_key(), er.session_key());
            assert_ne!(ei.session_key(), &[0u8; 32]);
            assert!(confirmed(&ei, &er));
            assert_eq!(ei.suite(), Suite::Hybrid);
            assert!(!ei.downgraded() && !er.downgraded());
            assert_eq!(m1.len(), HEADER_LEN + EK_LEN);
            assert_eq!(m2.len(), HEADER_LEN + CT_LEN);
            assert!(ei
                .agreed()
                .has_feature(super::super::capability::FEATURE_FRAGMENTATION));
        }
    }

    #[test]
    fn confirmation_tags_are_directional() {
        let (ci, cr) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
        let (ei, er, _, _) = run(ci, cr).unwrap();
        assert_ne!(ei.confirmation(), er.confirmation());
        // Reflecting our own tag back must not verify.
        assert!(ei.verify_peer_confirmation(&ei.confirmation()).is_err());
        assert!(er.verify_peer_confirmation(&er.confirmation()).is_err());
    }

    #[test]
    fn different_identity_gives_different_key() {
        let (ci, cr) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
        let mut cr2 = cr.clone();
        cr2.initiator_id = b"someone-else".to_vec();
        let mut g = ReplayGuard::new(4);
        let (init, m1) = Initiator::start(ci, &mut rng(1)).unwrap();
        let (er, m2) = Responder::accept(cr2, &m1, &mut g, &mut rng(2)).unwrap();
        let ei = init.finish(&m2).unwrap();
        assert_ne!(ei.session_key(), er.session_key());
        assert!(!confirmed(&ei, &er));
        let _ = cr;
    }

    // --- tampering ---------------------------------------------------------

    #[test]
    fn tampered_ciphertext_is_detected_and_keys_differ() {
        let (ci, cr) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
        let mut g = ReplayGuard::new(4);
        let (init, m1) = Initiator::start(ci, &mut rng(1)).unwrap();
        let (er, mut m2) = Responder::accept(cr, &m1, &mut g, &mut rng(2)).unwrap();
        m2[HEADER_LEN + 5] ^= 0x40;
        // Decapsulation itself does not fail (implicit rejection) ...
        let ei = init.finish(&m2).unwrap();
        // ... but the session key differs and confirmation fails.
        assert_ne!(ei.session_key(), er.session_key());
        assert!(!confirmed(&ei, &er));
    }

    #[test]
    fn tampered_x25519_public_is_detected() {
        let (ci, cr) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
        let mut g = ReplayGuard::new(4);
        let (init, m1) = Initiator::start(ci, &mut rng(1)).unwrap();
        let (er, mut m2) = Responder::accept(cr, &m1, &mut g, &mut rng(2)).unwrap();
        m2[10] ^= 1;
        let ei = init.finish(&m2).unwrap();
        assert_ne!(ei.session_key(), er.session_key());
        assert!(!confirmed(&ei, &er));
    }

    #[test]
    fn edited_capability_offer_is_detected_by_the_binding() {
        // An on-path party changes only a feature bit in what the initiator
        // sees. The suites still agree, so the messages parse, but the
        // transcripts differ and the confirmation fails.
        let honest = caps_hybrid();
        let mut seen_by_initiator = honest.clone();
        seen_by_initiator.features = 0;
        let ci = cfg(Mode::Strict, honest.clone(), seen_by_initiator);
        let cr = cfg(Mode::Strict, honest.clone(), honest);
        let (ei, er, _, _) = run(ci, cr).unwrap();
        assert_ne!(ei.session_key(), er.session_key());
        assert!(!confirmed(&ei, &er));
    }

    #[test]
    fn stripped_hybrid_offer_fails_closed_at_the_suite_check() {
        // The initiator is told the responder lacks the hybrid suite; the
        // responder knows it does. Initiator (compat) starts classical, the
        // responder expects hybrid and refuses.
        let honest = caps_hybrid();
        let mut stripped = honest.clone();
        stripped.suites = SUITE_CLASSICAL;
        let ci = cfg(Mode::Compatibility, honest.clone(), stripped);
        let cr = cfg(Mode::Compatibility, honest.clone(), honest);
        let mut g = ReplayGuard::new(4);
        let (_init, m1) = Initiator::start(ci, &mut rng(1)).unwrap();
        let err = Responder::accept(cr, &m1, &mut g, &mut rng(2)).unwrap_err();
        assert_eq!(err, HybridError::SuiteMismatch);
    }

    #[test]
    fn hybrid_agreed_but_message_without_kem_part_is_refused() {
        let (_ci, cr) = pair(
            Mode::Compatibility,
            caps_hybrid(),
            Mode::Compatibility,
            caps_hybrid(),
        );
        // A syntactically valid hybrid-suite message with kem_len = 0.
        let m1 = encode_msg(TAG_INITIATOR, SUITE_ID_HYBRID, &[9u8; 32], &[]);
        let mut g = ReplayGuard::new(4);
        assert_eq!(
            Responder::accept(cr, &m1, &mut g, &mut rng(2)).unwrap_err(),
            HybridError::HybridStripped
        );
    }

    // --- policy ------------------------------------------------------------

    #[test]
    fn legacy_peer_compat_runs_classical_with_visible_flag() {
        let (ci, cr) = pair(
            Mode::Compatibility,
            caps_hybrid(),
            Mode::Compatibility,
            Capabilities::legacy(),
        );
        let (ei, er, m1, m2) = run(ci, cr).unwrap();
        assert_eq!(ei.session_key(), er.session_key());
        assert!(confirmed(&ei, &er));
        assert_eq!(ei.suite(), Suite::ClassicalOnly);
        assert!(ei.downgraded(), "local offered hybrid, got classical");
        assert!(!ei.downgrade_reasons().is_empty());
        assert!(!er.downgraded(), "legacy side offered nothing more");
        assert_eq!(m1.len(), HEADER_LEN);
        assert_eq!(m2.len(), HEADER_LEN);
    }

    #[test]
    fn strict_local_fails_closed_before_sending_anything() {
        let (ci, _cr) = pair(
            Mode::Strict,
            caps_hybrid(),
            Mode::Compatibility,
            Capabilities::legacy(),
        );
        let err = Initiator::start(ci, &mut rng(1)).err().unwrap();
        assert!(matches!(err, HybridError::Negotiation(_)));
    }

    #[test]
    fn strict_applies_only_to_the_local_side() {
        // Responder strict, initiator legacy-capable: responder refuses.
        let (_ci, cr) = pair(
            Mode::Compatibility,
            Capabilities::legacy(),
            Mode::Strict,
            caps_hybrid(),
        );
        let mut g = ReplayGuard::new(4);
        let m1 = encode_msg(TAG_INITIATOR, SUITE_ID_CLASSICAL, &[9u8; 32], &[]);
        assert!(matches!(
            Responder::accept(cr, &m1, &mut g, &mut rng(2)).unwrap_err(),
            HybridError::Negotiation(_)
        ));
        // A compatibility-mode responder with the same peer simply goes
        // classical: the peer's lack is not a failure for it.
        let (_ci2, cr2) = pair(
            Mode::Compatibility,
            Capabilities::legacy(),
            Mode::Compatibility,
            caps_hybrid(),
        );
        assert!(Responder::accept(cr2, &m1, &mut g, &mut rng(3)).is_ok());
    }

    #[test]
    fn newer_peer_with_unknown_bits_still_gets_hybrid() {
        let mut newer = caps_hybrid();
        newer.version = 9;
        newer.suites |= 0xFFFF_0000;
        newer.features |= 0x8000_0000;
        let (ci, cr) = pair(Mode::Strict, caps_hybrid(), Mode::Compatibility, newer);
        let (ei, er, _, _) = run(ci, cr).unwrap();
        assert_eq!(ei.suite(), Suite::Hybrid);
        assert!(confirmed(&ei, &er));
    }

    // --- parsing -----------------------------------------------------------

    #[test]
    fn truncation_and_trailing_bytes_fail_closed() {
        let (ci, cr) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
        let (init, m1) = Initiator::start(ci, &mut rng(1)).unwrap();
        let mut g = ReplayGuard::new(4);
        for n in (0..m1.len()).step_by(37).chain([m1.len() - 1]) {
            assert!(
                Responder::accept(cr.clone(), &m1[..n], &mut g, &mut rng(2)).is_err(),
                "msg1 len {n}"
            );
        }
        let mut long = m1.clone();
        long.push(0);
        assert_eq!(
            Responder::accept(cr.clone(), &long, &mut g, &mut rng(2)).unwrap_err(),
            HybridError::TrailingBytes
        );
        let (_er, m2) = Responder::accept(cr, &m1, &mut g, &mut rng(2)).unwrap();
        for n in (0..m2.len()).step_by(37).chain([m2.len() - 1]) {
            // finish consumes self, so rebuild per attempt
            let (ci2, _) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
            let (i2, _) = Initiator::start(ci2, &mut rng(1)).unwrap();
            assert!(i2.finish(&m2[..n]).is_err(), "msg2 len {n}");
        }
        let mut long2 = m2.clone();
        long2.push(0);
        assert_eq!(init.finish(&long2).unwrap_err(), HybridError::TrailingBytes);
    }

    #[test]
    fn bad_header_fields_are_rejected() {
        let (ci, cr) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
        let (_i, m1) = Initiator::start(ci, &mut rng(1)).unwrap();
        let mut g = ReplayGuard::new(8);

        let mut bad = m1.clone();
        bad[0] = TAG_RESPONDER;
        assert_eq!(
            Responder::accept(cr.clone(), &bad, &mut g, &mut rng(2)).unwrap_err(),
            HybridError::BadTag(TAG_RESPONDER)
        );
        let mut bad = m1.clone();
        bad[1] = 9;
        assert_eq!(
            Responder::accept(cr.clone(), &bad, &mut g, &mut rng(2)).unwrap_err(),
            HybridError::BadVersion(9)
        );
        let mut bad = m1.clone();
        bad[3] = 1; // classical suite id on a hybrid exchange
        assert_eq!(
            Responder::accept(cr.clone(), &bad, &mut g, &mut rng(2)).unwrap_err(),
            HybridError::SuiteMismatch
        );
        let mut bad = m1.clone();
        bad[36..38].copy_from_slice(&((EK_LEN - 1) as u16).to_be_bytes());
        bad.pop();
        assert_eq!(
            Responder::accept(cr.clone(), &bad, &mut g, &mut rng(2)).unwrap_err(),
            HybridError::BadKemLength
        );
    }

    #[test]
    fn non_canonical_encapsulation_key_is_rejected() {
        let (ci, cr) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
        let (_i, mut m1) = Initiator::start(ci, &mut rng(1)).unwrap();
        // 0xFFF is above the field modulus 3329, so the key is invalid.
        m1[HEADER_LEN] = 0xFF;
        m1[HEADER_LEN + 1] = 0xFF;
        m1[HEADER_LEN + 2] = 0xFF;
        let mut g = ReplayGuard::new(4);
        assert_eq!(
            Responder::accept(cr, &m1, &mut g, &mut rng(2)).unwrap_err(),
            HybridError::InvalidKemKey
        );
    }

    #[test]
    fn low_order_x25519_point_is_rejected() {
        let (_ci, cr) = pair(
            Mode::Compatibility,
            Capabilities::legacy(),
            Mode::Compatibility,
            Capabilities::legacy(),
        );
        let m1 = encode_msg(TAG_INITIATOR, SUITE_ID_CLASSICAL, &[0u8; 32], &[]);
        let mut g = ReplayGuard::new(4);
        assert_eq!(
            Responder::accept(cr, &m1, &mut g, &mut rng(2)).unwrap_err(),
            HybridError::NonContributory
        );
    }

    #[test]
    fn replayed_first_message_is_refused() {
        let (ci, cr) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
        let (_i, m1) = Initiator::start(ci, &mut rng(1)).unwrap();
        let mut g = ReplayGuard::new(2);
        assert!(Responder::accept(cr.clone(), &m1, &mut g, &mut rng(2)).is_ok());
        assert_eq!(
            Responder::accept(cr.clone(), &m1, &mut g, &mut rng(3)).unwrap_err(),
            HybridError::Replay
        );
        // The guard is bounded: after two newer entries the oldest is forgotten.
        for seed in [11u64, 12] {
            let (c, _) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
            let (_x, m) = Initiator::start(c, &mut rng(seed)).unwrap();
            Responder::accept(cr.clone(), &m, &mut g, &mut rng(2)).unwrap();
        }
        assert!(Responder::accept(cr, &m1, &mut g, &mut rng(4)).is_ok());
    }

    #[test]
    fn failed_first_message_is_not_recorded_as_seen() {
        let (ci, cr) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
        let (_i, mut m1) = Initiator::start(ci, &mut rng(1)).unwrap();
        m1[HEADER_LEN] = 0xFF;
        m1[HEADER_LEN + 1] = 0xFF;
        m1[HEADER_LEN + 2] = 0xFF;
        let mut g = ReplayGuard::new(4);
        assert!(Responder::accept(cr.clone(), &m1, &mut g, &mut rng(2)).is_err());
        // Same failure again, not a Replay.
        assert_eq!(
            Responder::accept(cr, &m1, &mut g, &mut rng(2)).unwrap_err(),
            HybridError::InvalidKemKey
        );
    }

    // --- fragmentation -----------------------------------------------------

    fn deliver(frames: &[Vec<u8>], seed: u64) -> Assembled {
        let mut order: Vec<&Vec<u8>> = frames.iter().collect();
        // duplicates, then reorder
        order.push(&frames[0]);
        order.push(&frames[frames.len() - 1]);
        order.shuffle(&mut rng(seed));
        let mut r = MessageReassembler::new();
        let mut done = None;
        for f in order {
            if let Some(a) = r.push_frame(f, 0).unwrap() {
                assert!(done.is_none(), "completed twice");
                done = Some(a);
            }
        }
        // A duplicate arriving after completion only starts a harmless new
        // entry that never completes and expires.
        let a = done.expect("complete");
        r.expire(1_000_000);
        assert_eq!(r.in_progress(), 0);
        a
    }

    #[test]
    fn fragmented_reordered_duplicated_exchange_completes() {
        let (ci, cr) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
        let (init, m1) = Initiator::start(ci, &mut rng(1)).unwrap();
        let hid = 0xA1B2_C3D4_E5F6_0708;
        let frames1 = fragment_message(hid, init.suite_id(), &m1, 300).unwrap();
        assert!(frames1.len() > 3);
        assert!(frames1.iter().all(|f| f.len() <= 300 + 23));
        let a1 = deliver(&frames1, 5);
        assert_eq!((a1.handshake_id, a1.suite_id), (hid, SUITE_ID_HYBRID));
        assert_eq!(a1.data, m1);

        let mut g = ReplayGuard::new(4);
        let (er, m2) = Responder::accept(cr, &a1.data, &mut g, &mut rng(2)).unwrap();
        let frames2 = fragment_message(hid, SUITE_ID_HYBRID, &m2, 300).unwrap();
        let a2 = deliver(&frames2, 6);
        assert_eq!(a2.data, m2);
        let ei = init.finish(&a2.data).unwrap();
        assert_eq!(ei.session_key(), er.session_key());
        assert!(confirmed(&ei, &er));
    }

    #[test]
    fn conflicting_duplicate_fragment_is_rejected() {
        let (ci, _cr) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
        let (init, m1) = Initiator::start(ci, &mut rng(1)).unwrap();
        let frames = fragment_message(1, init.suite_id(), &m1, 300).unwrap();
        let mut r = MessageReassembler::new();
        r.push_frame(&frames[0], 0).unwrap();
        let mut evil = frames[0].clone();
        let last = evil.len() - 1;
        evil[last] ^= 1;
        assert!(matches!(
            r.push_frame(&evil, 0),
            Err(HybridError::Fragment(FragmentError::Conflict))
        ));
    }

    #[test]
    fn oversized_declared_message_is_refused_before_allocation() {
        let big =
            fragment_message(1, SUITE_ID_HYBRID, &vec![1u8; MAX_MESSAGE_LEN + 1], 500).unwrap();
        let mut r = MessageReassembler::new();
        assert!(matches!(
            r.push_frame(&big[0], 0),
            Err(HybridError::Fragment(FragmentError::BadTotalLen))
        ));
    }

    #[test]
    fn fragment_suite_must_match_message_suite() {
        let (ci, _cr) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
        let (_init, m1) = Initiator::start(ci, &mut rng(1)).unwrap();
        // Fragment headers claim the classical suite for a hybrid message.
        let frames = fragment_message(1, SUITE_ID_CLASSICAL, &m1, 600).unwrap();
        let mut r = MessageReassembler::new();
        let mut last = Ok(None);
        for f in &frames {
            last = r.push_frame(f, 0);
        }
        assert_eq!(last.unwrap_err(), HybridError::SuiteMismatch);
    }

    #[test]
    fn reassembly_state_expires() {
        let (ci, _cr) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
        let (init, m1) = Initiator::start(ci, &mut rng(1)).unwrap();
        let frames = fragment_message(1, init.suite_id(), &m1, 300).unwrap();
        let mut r = MessageReassembler::new();
        r.push_frame(&frames[0], 0).unwrap();
        assert_eq!(r.in_progress(), 1);
        assert_eq!(r.expire(20_000), 1);
        assert_eq!(r.in_progress(), 0);
    }

    // --- zeroization -------------------------------------------------------

    #[test]
    fn secrets_are_wiped_when_dropped() {
        let before = SECRET_DROPS.with(|c| c.get());
        {
            let (ci, cr) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
            let (ei, er, _, _) = run(ci, cr).unwrap();
            assert!(confirmed(&ei, &er));
        }
        let after = SECRET_DROPS.with(|c| c.get());
        // Per side: X25519 shared, ML-KEM shared, session key = 3 each. Every
        // drop asserts (inside Drop) that the bytes were zero afterwards.
        assert_eq!(after - before, 6);
    }

    #[test]
    fn secret_container_zeroes_its_bytes() {
        let mut s = Secret32([0xAB; 32]);
        s.0.zeroize();
        assert!(s.0.iter().all(|b| *b == 0));
    }

    #[test]
    fn debug_output_hides_the_key() {
        let (ci, cr) = pair(Mode::Strict, caps_hybrid(), Mode::Strict, caps_hybrid());
        let (ei, _, _, _) = run(ci, cr).unwrap();
        let shown = format!("{ei:?}");
        assert!(shown.contains("redacted"));
        assert!(!shown.contains(&hex::encode(ei.session_key())));
    }
}
