//! End-to-end encryption of one-to-one chat messages.
//!
//! ## Keys
//!
//! A contact's identity is an Ed25519 public key (the iroh endpoint ID). Both
//! sides can turn it into an X25519 key without any exchange:
//! `VerifyingKey::to_montgomery()` for the public half and
//! `SigningKey::to_scalar_bytes()` for the secret half (both are available in
//! the locked `ed25519-dalek` 2.2). That lets the first message be sealed while
//! the peer is offline: its long-term X25519 key plays the role of the
//! responder's signed pre-key, and no key server exists.
//!
//! ## Session
//!
//! The first flight is an X3DH-like agreement with two Diffie-Hellman values
//! (`DH(IK_a, IK_b)` and `DH(EK_a, IK_b)`), after which each pair runs the
//! Signal Double Ratchet: a Diffie-Hellman ratchet whenever the direction of
//! the conversation changes, and a symmetric ratchet for every message. Every
//! message gets its own key and nonce, so nothing is ever encrypted twice under
//! the same key. Message keys of skipped messages are kept (bounded) so that
//! messages arriving out of order still open.
//!
//! All key derivations are HKDF-SHA256 with the distinct labels below (the
//! `hmac` crate is not a dependency; HKDF-Expand is a PRF with the same role).
//! The cipher is XChaCha20-Poly1305. Plaintexts are padded (ISO/IEC 7816-4
//! style) to 512 B .. 16 KiB buckets, so the length of a ciphertext shows only
//! a coarse size class.
//!
//! ## Threat note
//!
//! Protected: the content of messages against anyone who records the traffic
//! (including the relay), against a peer that is not one of the two parties,
//! and, once the chain has advanced and the key was deleted, against a later
//! theft of this device's *session* state (forward secrecy per message).
//! After a theft the ratchet heals at the next round trip in each direction.
//!
//! Not protected: who talks to whom and when (the transport reveals endpoint
//! IDs and timing to the relay); the first messages of a session until the
//! peer has answered once, because they depend on the long-term key of the
//! recipient (if that key is stolen later, a recording of those first messages
//! can be read); messages saved in the local history (they are encrypted at
//! rest with the state key, but a device that is seized unlocked yields them);
//! a peer who keeps or forwards what it received.

use std::collections::VecDeque;

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Domain-separation labels. Fixed byte strings, never built from input; no
/// label is a prefix of another.
pub mod label {
    pub const X3DH: &[u8] = b"miasma/chat/v1/x3dh";
    pub const ROOT: &[u8] = b"miasma/chat/v1/rk";
    pub const CHAIN: &[u8] = b"miasma/chat/v1/ck";
    pub const MESSAGE: &[u8] = b"miasma/chat/v1/msgkey";
    /// Optional second layer of a message key (see `chat::pq`); used only
    /// after a hybrid exchange completed in the session.
    pub const PQ_LAYER: &[u8] = b"miasma/chat/v1/pqlayer";
    pub const FILE_NAME: &str = "miasma chat v1 file name";
}

pub const ENVELOPE_VERSION: u8 = 1;
/// The only suite: Double Ratchet with XChaCha20-Poly1305.
pub const SUITE_RATCHET: u8 = 2;
/// A message between two people (the only kind in this version).
pub const KIND_PAIR: u8 = 1;

/// Message keys derived ahead for one chain advance, at most.
pub const MAX_SKIP: u32 = 256;
/// Message keys kept for messages that have not arrived yet, per session.
pub const MAX_STORED_SKIPPED: usize = 1024;

/// Padded plaintext sizes. A plaintext uses the smallest bucket that fits it
/// plus the one-byte padding marker.
pub const PAD_BUCKETS: [usize; 6] = [512, 1024, 2048, 4096, 8192, 16384];
pub const MAX_PADDED: usize = 16384;
pub const TAG_LEN: usize = 16;
/// Longest ciphertext (padded plaintext plus tag).
pub const MAX_CIPHERTEXT: usize = MAX_PADDED + TAG_LEN;
/// The part of an envelope in front of the ciphertext never exceeds this.
pub const MAX_HEADER_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("not a valid identity key")]
    BadKey,
    #[error("the key exchange produced no shared secret")]
    NonContributory,
    #[error("unsupported envelope version {0}")]
    Version(u8),
    #[error("unsupported cipher suite or message kind")]
    Unsupported,
    #[error("malformed envelope: {0}")]
    Malformed(&'static str),
    #[error("message too large")]
    TooLarge,
    #[error("the message did not authenticate")]
    Authentication,
    #[error("this message was already received")]
    Replay,
    #[error("too many messages missing before this one")]
    TooFarAhead,
    #[error("no chain to send on yet")]
    NoSendChain,
    #[error("damaged session data")]
    BadState,
}

// ─── Identity ────────────────────────────────────────────────────────────────

/// This node's chat identity: the Ed25519 endpoint ID and the X25519 key that
/// belongs to it.
pub struct Identity {
    id: [u8; 32],
    dh_secret: StaticSecret,
    dh_public: [u8; 32],
}

impl Identity {
    /// From the 32-byte Ed25519 seed the iroh endpoint is created from.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(seed);
        let id = sk.verifying_key().to_bytes();
        let mut scalar = Zeroizing::new(sk.to_scalar_bytes());
        let dh_secret = StaticSecret::from(*scalar);
        scalar.zeroize();
        let dh_public = PublicKey::from(&dh_secret).to_bytes();
        Self {
            id,
            dh_secret,
            dh_public,
        }
    }

    /// The Ed25519 public key (endpoint ID).
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    pub fn dh_public(&self) -> [u8; 32] {
        self.dh_public
    }
}

/// The X25519 public key that belongs to an Ed25519 endpoint ID.
pub fn peer_dh_public(endpoint_id: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let vk = VerifyingKey::from_bytes(endpoint_id).map_err(|_| CryptoError::BadKey)?;
    if vk.is_weak() {
        return Err(CryptoError::BadKey);
    }
    Ok(vk.to_montgomery().to_bytes())
}

fn dh(secret: &StaticSecret, public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let shared = secret.diffie_hellman(&PublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(CryptoError::NonContributory);
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

/// A buffer of `N` random bytes, zeroized on drop. Used as the output buffer of the
/// KDFs (no literal constant ever sits where key material goes).
fn fresh<const N: usize>() -> Zeroizing<[u8; N]> {
    Zeroizing::new(std::array::from_fn(|_| rand::random::<u8>()))
}

fn random_secret() -> StaticSecret {
    StaticSecret::random_from_rng(rand::rngs::OsRng)
}

// ─── KDFs ────────────────────────────────────────────────────────────────────

fn kdf_root(
    root: &[u8; 32],
    dh_out: &[u8; 32],
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(root), dh_out);
    let mut out = fresh::<64>();
    hk.expand(label::ROOT, out.as_mut())
        .map_err(|_| CryptoError::BadState)?;
    let mut rk = fresh::<32>();
    let mut ck = fresh::<32>();
    rk.copy_from_slice(&out[..32]);
    ck.copy_from_slice(&out[32..]);
    Ok((rk, ck))
}

/// One step of the symmetric ratchet: the next chain key, the message key and
/// the message nonce.
struct Step {
    next: Zeroizing<[u8; 32]>,
    key: Zeroizing<[u8; 32]>,
    nonce: [u8; 24],
}

fn kdf_chain(ck: &[u8; 32]) -> Result<Step, CryptoError> {
    let hk = Hkdf::<Sha256>::from_prk(ck).map_err(|_| CryptoError::BadState)?;
    let mut next = fresh::<32>();
    hk.expand(label::CHAIN, next.as_mut())
        .map_err(|_| CryptoError::BadState)?;
    let mut mat = fresh::<56>();
    hk.expand(label::MESSAGE, mat.as_mut())
        .map_err(|_| CryptoError::BadState)?;
    let mut key = fresh::<32>();
    key.copy_from_slice(&mat[..32]);
    let mut nonce: [u8; 24] = rand::random();
    nonce.copy_from_slice(&mat[32..]);
    Ok(Step { next, key, nonce })
}

/// The key of a message that is protected by the hybrid key `pq` as well as by
/// the ratchet: both feed one HKDF, bound to the position of the message
/// (`dh`, `n`), so learning one of the two inputs is not enough. Only a session
/// that completed the hybrid exchange passes a `pq` key; for everyone else this
/// function is never reached with `Some`.
fn layer_key(
    msg_key: &[u8; 32],
    pq: &[u8; 32],
    dh: &[u8; 32],
    n: u32,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut ikm = fresh::<64>();
    ikm[..32].copy_from_slice(msg_key);
    ikm[32..].copy_from_slice(pq);
    let mut info = Vec::with_capacity(36);
    info.extend_from_slice(dh);
    info.extend_from_slice(&n.to_be_bytes());
    let hk = Hkdf::<Sha256>::new(Some(label::PQ_LAYER), ikm.as_ref());
    let mut out = fresh::<32>();
    hk.expand(&info, out.as_mut())
        .map_err(|_| CryptoError::BadState)?;
    Ok(out)
}

/// Open one message: with the hybrid layer first when the receiver holds a
/// hybrid key (the sender may not have switched to it yet, so the plain key is
/// tried second). The AEAD tag decides; a forged message opens under neither.
fn open_msg(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ct: &[u8],
    layer: Option<&[u8; 32]>,
    dh: &[u8; 32],
    n: u32,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if let Some(pq) = layer {
        let lk = layer_key(key, pq, dh, n)?;
        if let Ok(pt) = aead_open(&lk, nonce, aad, ct) {
            return Ok(pt);
        }
    }
    aead_open(key, nonce, aad, ct)
}

/// The session secret from the first-flight Diffie-Hellman values.
fn kdf_first_flight(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    id_a: &[u8; 32],
    id_b: &[u8; 32],
    ek_pub: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut ikm = fresh::<64>();
    ikm[..32].copy_from_slice(dh1);
    ikm[32..].copy_from_slice(dh2);
    let mut info = Vec::with_capacity(96);
    info.extend_from_slice(id_a);
    info.extend_from_slice(id_b);
    info.extend_from_slice(ek_pub);
    let hk = Hkdf::<Sha256>::new(Some(label::X3DH), ikm.as_ref());
    let mut out = fresh::<32>();
    hk.expand(&info, out.as_mut())
        .map_err(|_| CryptoError::BadState)?;
    Ok(out)
}

// ─── Padding ─────────────────────────────────────────────────────────────────

/// Pad `data` to the smallest bucket that holds it plus the marker byte.
pub fn pad(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let need = data.len() + 1;
    let bucket = PAD_BUCKETS
        .iter()
        .copied()
        .find(|b| *b >= need)
        .ok_or(CryptoError::TooLarge)?;
    let mut v = Zeroizing::new(Vec::with_capacity(bucket + TAG_LEN));
    v.extend_from_slice(data);
    v.push(0x80);
    v.resize(bucket, 0);
    Ok(v)
}

/// Remove the padding; the padded length must be a bucket size.
pub fn unpad(padded: &mut Vec<u8>) -> Result<(), CryptoError> {
    if !PAD_BUCKETS.contains(&padded.len()) {
        return Err(CryptoError::Malformed("padding length"));
    }
    while let Some(&last) = padded.last() {
        match last {
            0 => {
                padded.pop();
            }
            0x80 => {
                padded.pop();
                return Ok(());
            }
            _ => break,
        }
    }
    Err(CryptoError::Malformed("padding marker"))
}

// ─── Envelope ────────────────────────────────────────────────────────────────

/// What travels with a ciphertext in the clear (but authenticated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The sender's current ratchet public key.
    pub dh_pub: [u8; 32],
    /// Messages in the sender's previous sending chain.
    pub pn: u32,
    /// Index of this message in the current sending chain.
    pub n: u32,
    /// The first-flight ephemeral public key, present until the sender has
    /// received something in this session.
    pub init_ek: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Random, for transport-level de-duplication; not secret.
    pub id: [u8; 16],
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    fn header_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(96);
        v.extend_from_slice(&self.header.dh_pub);
        v.extend_from_slice(&self.header.pn.to_be_bytes());
        v.extend_from_slice(&self.header.n.to_be_bytes());
        match &self.header.init_ek {
            Some(ek) => {
                v.push(1);
                v.extend_from_slice(ek);
            }
            None => v.push(0),
        }
        v
    }

    /// `ver | suite | kind | id | header | ct_len | ct`
    pub fn encode(&self) -> Vec<u8> {
        let hb = self.header_bytes();
        let mut v = Vec::with_capacity(3 + 16 + hb.len() + 4 + self.ciphertext.len());
        v.push(ENVELOPE_VERSION);
        v.push(SUITE_RATCHET);
        v.push(KIND_PAIR);
        v.extend_from_slice(&self.id);
        v.extend_from_slice(&hb);
        v.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        v.extend_from_slice(&self.ciphertext);
        v
    }

    /// Strict decoder: every length is checked before anything is sized, and
    /// trailing bytes are an error.
    pub fn decode(b: &[u8]) -> Result<Self, CryptoError> {
        let mut r = Rd::new(b);
        let ver = r.u8().map_err(|_| CryptoError::Malformed("short"))?;
        if ver != ENVELOPE_VERSION {
            return Err(CryptoError::Version(ver));
        }
        let suite = r.u8().map_err(|_| CryptoError::Malformed("short"))?;
        let kind = r.u8().map_err(|_| CryptoError::Malformed("short"))?;
        if suite != SUITE_RATCHET || kind != KIND_PAIR {
            return Err(CryptoError::Unsupported);
        }
        let short = |_| CryptoError::Malformed("short");
        let id = r.arr::<16>().map_err(short)?;
        let dh_pub = r.arr::<32>().map_err(short)?;
        let pn = r.u32().map_err(short)?;
        let n = r.u32().map_err(short)?;
        let init_ek = match r.u8().map_err(short)? {
            0 => None,
            1 => Some(r.arr::<32>().map_err(short)?),
            _ => return Err(CryptoError::Malformed("init flag")),
        };
        if r.pos() > MAX_HEADER_BYTES {
            return Err(CryptoError::Malformed("header"));
        }
        let ct_len = r.u32().map_err(short)? as usize;
        if !(TAG_LEN..=MAX_CIPHERTEXT).contains(&ct_len) {
            return Err(CryptoError::Malformed("ciphertext length"));
        }
        let ct = r.bytes(ct_len).map_err(short)?.to_vec();
        if !r.done() {
            return Err(CryptoError::Malformed("trailing bytes"));
        }
        Ok(Self {
            id,
            header: Header {
                dh_pub,
                pn,
                n,
                init_ek,
            },
            ciphertext: ct,
        })
    }
}

fn aad(env: &Envelope, sender: &[u8; 32], recipient: &[u8; 32]) -> Vec<u8> {
    let hb = env.header_bytes();
    let mut a = Vec::with_capacity(3 + 16 + hb.len() + 64);
    a.push(ENVELOPE_VERSION);
    a.push(SUITE_RATCHET);
    a.push(KIND_PAIR);
    a.extend_from_slice(&env.id);
    a.extend_from_slice(&hb);
    a.extend_from_slice(sender);
    a.extend_from_slice(recipient);
    a
}

fn aead_seal(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    buf: &mut Vec<u8>,
) -> Result<(), CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(nonce), aad, buf.as_mut_slice())
        .map_err(|_| CryptoError::BadState)?;
    buf.extend_from_slice(&tag);
    Ok(())
}

fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if ct.len() < TAG_LEN {
        return Err(CryptoError::Authentication);
    }
    let (body, tag) = ct.split_at(ct.len() - TAG_LEN);
    let mut buf = Zeroizing::new(body.to_vec());
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(nonce),
            aad,
            buf.as_mut_slice(),
            Tag::from_slice(tag),
        )
        .map_err(|_| CryptoError::Authentication)?;
    Ok(buf)
}

// ─── Session ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Skipped {
    dh: [u8; 32],
    n: u32,
    key: Zeroizing<[u8; 32]>,
    nonce: [u8; 24],
}

/// The Double Ratchet state of one pair.
#[derive(Clone)]
pub struct Session {
    own_id: [u8; 32],
    peer_id: [u8; 32],
    root: Zeroizing<[u8; 32]>,
    dhs: StaticSecret,
    dhs_pub: [u8; 32],
    dhr: Option<[u8; 32]>,
    cks: Option<Zeroizing<[u8; 32]>>,
    ckr: Option<Zeroizing<[u8; 32]>>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: VecDeque<Skipped>,
    /// The first-flight ephemeral key that created this session (ours as
    /// initiator, the peer's as responder).
    origin_ek: [u8; 32],
    initiator: bool,
    /// Initiator only: nothing has been received yet, so every message still
    /// carries the first-flight key.
    pending_init: bool,
}

const STATE_VERSION: u8 = 1;

impl Session {
    /// Start a session towards `peer_id` (we write first).
    pub fn new_initiator(me: &Identity, peer_id: &[u8; 32]) -> Result<Self, CryptoError> {
        let peer_dh = peer_dh_public(peer_id)?;
        let ek = random_secret();
        let ek_pub = PublicKey::from(&ek).to_bytes();
        let dh1 = dh(&me.dh_secret, &peer_dh)?;
        let dh2 = dh(&ek, &peer_dh)?;
        let sk = kdf_first_flight(&dh1, &dh2, &me.id, peer_id, &ek_pub)?;
        let ratchet = random_secret();
        let ratchet_pub = PublicKey::from(&ratchet).to_bytes();
        let shared = dh(&ratchet, &peer_dh)?;
        let (root, cks) = kdf_root(&sk, &shared)?;
        Ok(Self {
            own_id: me.id,
            peer_id: *peer_id,
            root,
            dhs: ratchet,
            dhs_pub: ratchet_pub,
            dhr: Some(peer_dh),
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: VecDeque::new(),
            origin_ek: ek_pub,
            initiator: true,
            pending_init: true,
        })
    }

    /// The state of a responder before it has opened the first message: it
    /// cannot send until [`open`](Self::open) succeeded.
    fn new_responder(
        me: &Identity,
        peer_id: &[u8; 32],
        peer_ek: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        let peer_dh = peer_dh_public(peer_id)?;
        let dh1 = dh(&me.dh_secret, &peer_dh)?;
        let dh2 = dh(&me.dh_secret, peer_ek)?;
        let sk = kdf_first_flight(&dh1, &dh2, peer_id, &me.id, peer_ek)?;
        Ok(Self {
            own_id: me.id,
            peer_id: *peer_id,
            root: sk,
            dhs: me.dh_secret.clone(),
            dhs_pub: me.dh_public,
            dhr: None,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: VecDeque::new(),
            origin_ek: *peer_ek,
            initiator: false,
            pending_init: false,
        })
    }

    /// Create the responder session for a first-flight message and open it. The
    /// session exists only if the message authenticates.
    pub fn accept(
        me: &Identity,
        peer_id: &[u8; 32],
        env: &Envelope,
    ) -> Result<(Self, Zeroizing<Vec<u8>>), CryptoError> {
        let ek = env
            .header
            .init_ek
            .ok_or(CryptoError::Malformed("no first-flight key"))?;
        let mut s = Self::new_responder(me, peer_id, &ek)?;
        let pt = s.open(env)?;
        Ok((s, pt))
    }

    pub fn peer_id(&self) -> &[u8; 32] {
        &self.peer_id
    }

    /// The first-flight key that created this session.
    pub fn origin_ek(&self) -> &[u8; 32] {
        &self.origin_ek
    }

    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    /// True while we have written but never received in this session.
    pub fn awaiting_first_reply(&self) -> bool {
        self.pending_init
    }

    /// Number of message keys kept for messages that have not arrived.
    pub fn skipped_len(&self) -> usize {
        self.skipped.len()
    }

    /// Encrypt one plaintext into an envelope. The caller persists the session
    /// before the envelope leaves the machine (so a key is never used twice).
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Envelope, CryptoError> {
        self.seal_with(plaintext, None)
    }

    /// As [`seal`](Self::seal); with `layer` the message key is combined with
    /// the hybrid key of this session (see `chat::pq`). The envelope bytes have
    /// the same shape either way.
    pub fn seal_with(
        &mut self,
        plaintext: &[u8],
        layer: Option<&[u8; 32]>,
    ) -> Result<Envelope, CryptoError> {
        let padded = pad(plaintext)?;
        let cks = self.cks.as_ref().ok_or(CryptoError::NoSendChain)?;
        let step = kdf_chain(cks)?;
        let mut id: [u8; 16] = rand::random();
        rand::rngs::OsRng.fill_bytes(&mut id);
        let mut env = Envelope {
            id,
            header: Header {
                dh_pub: self.dhs_pub,
                pn: self.pn,
                n: self.ns,
                init_ek: if self.pending_init {
                    Some(self.origin_ek)
                } else {
                    None
                },
            },
            ciphertext: Vec::new(),
        };
        let a = aad(&env, &self.own_id, &self.peer_id);
        let mut buf = padded;
        match layer {
            Some(pq) => {
                let lk = layer_key(&step.key, pq, &self.dhs_pub, self.ns)?;
                aead_seal(&lk, &step.nonce, &a, &mut buf)?;
            }
            None => aead_seal(&step.key, &step.nonce, &a, &mut buf)?,
        }
        env.ciphertext = std::mem::take(&mut *buf);
        self.cks = Some(step.next);
        self.ns = self.ns.checked_add(1).ok_or(CryptoError::BadState)?;
        Ok(env)
    }

    /// Decrypt an envelope from the peer. The session changes only when the
    /// message authenticates; a forged, damaged or replayed message leaves it
    /// untouched.
    pub fn open(&mut self, env: &Envelope) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.open_with(env, None)
    }

    /// As [`open`](Self::open); with `layer` a message that was protected by
    /// the hybrid key of this session opens too (a plain one still does).
    pub fn open_with(
        &mut self,
        env: &Envelope,
        layer: Option<&[u8; 32]>,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let a = aad(env, &self.peer_id, &self.own_id);
        // A message whose key was kept for it.
        if let Some(pos) = self
            .skipped
            .iter()
            .position(|s| s.dh == env.header.dh_pub && s.n == env.header.n)
        {
            let s = &self.skipped[pos];
            let mut pt = open_msg(&s.key, &s.nonce, &a, &env.ciphertext, layer, &s.dh, s.n)?;
            unpad(&mut pt)?;
            self.skipped.remove(pos);
            return Ok(pt);
        }
        let mut next = self.clone();
        if next.dhr.as_ref() != Some(&env.header.dh_pub) {
            next.skip_until(env.header.pn)?;
            next.dh_ratchet(&env.header.dh_pub)?;
        } else if env.header.n < next.nr {
            return Err(CryptoError::Replay);
        }
        next.skip_until(env.header.n)?;
        let ckr = next.ckr.as_ref().ok_or(CryptoError::Authentication)?;
        let step = kdf_chain(ckr)?;
        let mut pt = open_msg(
            &step.key,
            &step.nonce,
            &a,
            &env.ciphertext,
            layer,
            &env.header.dh_pub,
            env.header.n,
        )?;
        unpad(&mut pt)?;
        next.ckr = Some(step.next);
        next.nr = next.nr.checked_add(1).ok_or(CryptoError::BadState)?;
        next.pending_init = false;
        *self = next;
        Ok(pt)
    }

    /// Keep the message keys of the receiving chain up to (not including) `until`.
    fn skip_until(&mut self, until: u32) -> Result<(), CryptoError> {
        let Some(mut ck) = self.ckr.clone() else {
            return Ok(());
        };
        if until <= self.nr {
            return Ok(());
        }
        if until - self.nr > MAX_SKIP {
            return Err(CryptoError::TooFarAhead);
        }
        let dh = self.dhr.ok_or(CryptoError::BadState)?;
        while self.nr < until {
            let step = kdf_chain(&ck)?;
            if self.skipped.len() >= MAX_STORED_SKIPPED {
                self.skipped.pop_front();
            }
            self.skipped.push_back(Skipped {
                dh,
                n: self.nr,
                key: step.key,
                nonce: step.nonce,
            });
            ck = step.next;
            self.nr += 1;
        }
        self.ckr = Some(ck);
        Ok(())
    }

    fn dh_ratchet(&mut self, peer_pub: &[u8; 32]) -> Result<(), CryptoError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(*peer_pub);
        let shared = dh(&self.dhs, peer_pub)?;
        let (root, ckr) = kdf_root(&self.root, &shared)?;
        self.root = root;
        self.ckr = Some(ckr);
        self.dhs = random_secret();
        self.dhs_pub = PublicKey::from(&self.dhs).to_bytes();
        let shared = dh(&self.dhs, peer_pub)?;
        let (root, cks) = kdf_root(&self.root, &shared)?;
        self.root = root;
        self.cks = Some(cks);
        Ok(())
    }

    // ── Persistence (the caller encrypts the bytes at rest) ──────────────────

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Zeroizing::new(Vec::with_capacity(512 + self.skipped.len() * 64));
        w.push(STATE_VERSION);
        w.extend_from_slice(&self.own_id);
        w.extend_from_slice(&self.peer_id);
        w.extend_from_slice(self.root.as_ref());
        let secret = Zeroizing::new(self.dhs.to_bytes());
        w.extend_from_slice(secret.as_ref());
        w.extend_from_slice(&self.dhs_pub);
        put_opt32(&mut w, self.dhr.as_ref());
        put_opt32(&mut w, self.cks.as_deref());
        put_opt32(&mut w, self.ckr.as_deref());
        w.extend_from_slice(&self.ns.to_be_bytes());
        w.extend_from_slice(&self.nr.to_be_bytes());
        w.extend_from_slice(&self.pn.to_be_bytes());
        w.extend_from_slice(&self.origin_ek);
        w.push(u8::from(self.initiator) | (u8::from(self.pending_init) << 1));
        w.extend_from_slice(&(self.skipped.len() as u32).to_be_bytes());
        for s in &self.skipped {
            w.extend_from_slice(&s.dh);
            w.extend_from_slice(&s.n.to_be_bytes());
            w.extend_from_slice(s.key.as_ref());
            w.extend_from_slice(&s.nonce);
        }
        w
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        let bad = |_| CryptoError::BadState;
        let mut r = Rd::new(b);
        if r.u8().map_err(bad)? != STATE_VERSION {
            return Err(CryptoError::BadState);
        }
        let own_id = r.arr::<32>().map_err(bad)?;
        let peer_id = r.arr::<32>().map_err(bad)?;
        let root = Zeroizing::new(r.arr::<32>().map_err(bad)?);
        let mut secret = Zeroizing::new(r.arr::<32>().map_err(bad)?);
        let dhs = StaticSecret::from(*secret);
        secret.zeroize();
        let dhs_pub = r.arr::<32>().map_err(bad)?;
        if PublicKey::from(&dhs).to_bytes() != dhs_pub {
            return Err(CryptoError::BadState);
        }
        let dhr = get_opt32(&mut r)?;
        let cks = get_opt32(&mut r)?.map(Zeroizing::new);
        let ckr = get_opt32(&mut r)?.map(Zeroizing::new);
        let ns = r.u32().map_err(bad)?;
        let nr = r.u32().map_err(bad)?;
        let pn = r.u32().map_err(bad)?;
        let origin_ek = r.arr::<32>().map_err(bad)?;
        let flags = r.u8().map_err(bad)?;
        let count = r.u32().map_err(bad)? as usize;
        if count > MAX_STORED_SKIPPED {
            return Err(CryptoError::BadState);
        }
        let mut skipped = VecDeque::with_capacity(count);
        for _ in 0..count {
            skipped.push_back(Skipped {
                dh: r.arr::<32>().map_err(bad)?,
                n: r.u32().map_err(bad)?,
                key: Zeroizing::new(r.arr::<32>().map_err(bad)?),
                nonce: r.arr::<24>().map_err(bad)?,
            });
        }
        if !r.done() {
            return Err(CryptoError::BadState);
        }
        Ok(Self {
            own_id,
            peer_id,
            root,
            dhs,
            dhs_pub,
            dhr,
            cks,
            ckr,
            ns,
            nr,
            pn,
            skipped,
            origin_ek,
            initiator: flags & 1 != 0,
            pending_init: flags & 2 != 0,
        })
    }
}

fn put_opt32(w: &mut Vec<u8>, v: Option<&[u8; 32]>) {
    match v {
        Some(k) => {
            w.push(1);
            w.extend_from_slice(k);
        }
        None => w.push(0),
    }
}

fn get_opt32(r: &mut Rd<'_>) -> Result<Option<[u8; 32]>, CryptoError> {
    match r.u8().map_err(|_| CryptoError::BadState)? {
        0 => Ok(None),
        1 => Ok(Some(r.arr::<32>().map_err(|_| CryptoError::BadState)?)),
        _ => Err(CryptoError::BadState),
    }
}

// ─── Byte reader ─────────────────────────────────────────────────────────────

/// A bounds-checked cursor. Also used by the other chat codecs.
pub(crate) struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

pub(crate) struct Short;

impl<'a> Rd<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    pub fn pos(&self) -> usize {
        self.p
    }
    pub fn done(&self) -> bool {
        self.p == self.b.len()
    }
    pub fn remaining(&self) -> usize {
        self.b.len() - self.p
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Short> {
        if self.remaining() < n {
            return Err(Short);
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, Short> {
        Ok(self.bytes(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, Short> {
        Ok(u16::from_be_bytes(self.arr::<2>()?))
    }
    pub fn u32(&mut self) -> Result<u32, Short> {
        Ok(u32::from_be_bytes(self.arr::<4>()?))
    }
    pub fn u64(&mut self) -> Result<u64, Short> {
        Ok(u64::from_be_bytes(self.arr::<8>()?))
    }
    pub fn arr<const N: usize>(&mut self) -> Result<[u8; N], Short> {
        <[u8; N]>::try_from(self.bytes(N)?).map_err(|_| Short)
    }
}

/// Name of a conversation's files: a keyed hash of the peer ID, so the file
/// names say nothing about who it is.
pub fn file_stem(own_id: &[u8; 32], peer_id: &[u8; 32]) -> String {
    let mut h = blake3::Hasher::new_derive_key(label::FILE_NAME);
    h.update(own_id);
    h.update(peer_id);
    hex::encode(&h.finalize().as_bytes()[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Identity, Identity) {
        let a = Identity::from_seed(&rand::random());
        let b = Identity::from_seed(&rand::random());
        (a, b)
    }

    /// Alice writes first; returns both session halves after Bob accepted
    /// the first message.
    fn established() -> (Identity, Identity, Session, Session) {
        let (a, b) = pair();
        let mut sa = Session::new_initiator(&a, &b.id()).unwrap();
        let env = sa.seal(b"first").unwrap();
        let (sb, pt) = Session::accept(&b, &a.id(), &env).unwrap();
        assert_eq!(&**pt, b"first");
        (a, b, sa, sb)
    }

    #[test]
    fn identity_conversion_matches_between_the_two_halves() {
        let seed: [u8; 32] = rand::random();
        let me = Identity::from_seed(&seed);
        // The public conversion done by a peer from the endpoint ID alone
        // equals the public key of the converted secret.
        assert_eq!(peer_dh_public(&me.id()).unwrap(), me.dh_public());
    }

    #[test]
    fn labels_are_distinct_and_none_is_a_prefix_of_another() {
        let all = [label::X3DH, label::ROOT, label::CHAIN, label::MESSAGE];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                    assert!(!b.starts_with(a), "{:?} prefixes {:?}", a, b);
                }
            }
        }
    }

    #[test]
    fn conversation_works_in_both_directions_and_across_dh_steps() {
        let (_a, _b, mut sa, mut sb) = established();
        for round in 0..6u8 {
            let m = sb.seal(&[round; 40]).unwrap();
            assert!(m.header.init_ek.is_none());
            assert_eq!(&**sa.open(&m).unwrap(), &[round; 40][..]);
            for k in 0..3u8 {
                let m = sa.seal(&[round, k]).unwrap();
                assert_eq!(&**sb.open(&m).unwrap(), &[round, k][..]);
            }
        }
    }

    #[test]
    fn first_flight_carries_the_key_until_the_first_reply() {
        let (a, b) = pair();
        let mut sa = Session::new_initiator(&a, &b.id()).unwrap();
        let m1 = sa.seal(b"1").unwrap();
        let m2 = sa.seal(b"2").unwrap();
        assert!(m1.header.init_ek.is_some() && m2.header.init_ek.is_some());
        let (mut sb, _) = Session::accept(&b, &a.id(), &m1).unwrap();
        sb.open(&m2).unwrap();
        let r = sb.seal(b"hi").unwrap();
        sa.open(&r).unwrap();
        assert!(sa.seal(b"3").unwrap().header.init_ek.is_none());
    }

    #[test]
    fn out_of_order_and_dropped_messages_open_exactly_once() {
        let (_a, _b, mut sa, mut sb) = established();
        let msgs: Vec<Envelope> = (0..10u8).map(|i| sa.seal(&[i]).unwrap()).collect();
        for i in [9usize, 3, 0, 7, 1, 2, 8] {
            assert_eq!(&**sb.open(&msgs[i]).unwrap(), &[i as u8][..]);
        }
        // 4, 5, 6 never arrive; a delivered one cannot be delivered again.
        for i in [9usize, 3, 0, 7, 1, 2, 8] {
            assert!(sb.open(&msgs[i]).is_err());
        }
        assert_eq!(&**sb.open(&msgs[5]).unwrap(), &[5u8][..]);
    }

    #[test]
    fn out_of_order_across_a_dh_step() {
        let (_a, _b, mut sa, mut sb) = established();
        let old1 = sa.seal(b"old1").unwrap();
        let old2 = sa.seal(b"old2").unwrap();
        // Bob answers after seeing only `old1`... in the middle of a chain.
        let (_, _) = (&old1, &old2);
        let r = sb.seal(b"reply").unwrap();
        sa.open(&r).unwrap();
        let new1 = sa.seal(b"new1").unwrap();
        // The new chain arrives first; the old ones afterwards.
        assert_eq!(&**sb.open(&new1).unwrap(), b"new1");
        assert_eq!(&**sb.open(&old2).unwrap(), b"old2");
        assert_eq!(&**sb.open(&old1).unwrap(), b"old1");
    }

    #[test]
    fn replay_is_rejected_and_leaves_the_session_usable() {
        let (_a, _b, mut sa, mut sb) = established();
        let m = sa.seal(b"once").unwrap();
        sb.open(&m).unwrap();
        assert_eq!(sb.open(&m), Err(CryptoError::Replay));
        let next = sa.seal(b"next").unwrap();
        assert_eq!(&**sb.open(&next).unwrap(), b"next");
    }

    #[test]
    fn tampering_with_any_part_is_rejected_without_changing_state() {
        let (_a, _b, mut sa, mut sb) = established();
        let m = sa.seal(b"payload").unwrap();
        let wire = m.encode();
        for i in 0..wire.len() {
            let mut bad = wire.clone();
            bad[i] ^= 0x01;
            // Either the codec refuses it or the AEAD does.
            if let Ok(e) = Envelope::decode(&bad) {
                assert!(sb.open(&e).is_err(), "flip at byte {i} was accepted");
            }
        }
        assert_eq!(&**sb.open(&m).unwrap(), b"payload");
    }

    #[test]
    fn a_message_for_another_recipient_does_not_open() {
        let (a, b, mut sa, _sb) = established();
        let c = Identity::from_seed(&rand::random());
        let m = sa.seal(b"for b").unwrap();
        assert!(Session::accept(&c, &a.id(), &m).is_err());
        assert!(Session::accept(&b, &c.id(), &m).is_err());
    }

    #[test]
    fn too_many_missing_messages_is_refused() {
        let (_a, _b, mut sa, mut sb) = established();
        let mut last = None;
        for i in 0..(MAX_SKIP + 5) {
            last = Some(sa.seal(&i.to_be_bytes()).unwrap());
        }
        assert_eq!(sb.open(&last.unwrap()), Err(CryptoError::TooFarAhead));
    }

    #[test]
    fn stored_skipped_keys_are_bounded() {
        let (_a, _b, mut sa, mut sb) = established();
        for _ in 0..8 {
            // Lose MAX_SKIP messages each time, receive the one after.
            for _ in 0..MAX_SKIP {
                sa.seal(b"lost").unwrap();
            }
            let m = sa.seal(b"seen").unwrap();
            sb.open(&m).unwrap();
        }
        assert!(sb.skipped_len() <= MAX_STORED_SKIPPED);
    }

    #[test]
    fn state_survives_serialisation_in_the_middle_of_a_conversation() {
        let (a, b, mut sa, mut sb) = established();
        let m = sa.seal(b"x").unwrap();
        let held_back = sa.seal(b"y").unwrap();
        sb.open(&m).unwrap();
        let r = sb.seal(b"r").unwrap();
        sa.open(&r).unwrap();
        let mut sa2 = Session::from_bytes(&sa.to_bytes()).unwrap();
        let mut sb2 = Session::from_bytes(&sb.to_bytes()).unwrap();
        let n = sa2.seal(b"after restart").unwrap();
        assert_eq!(&**sb2.open(&n).unwrap(), b"after restart");
        assert_eq!(&**sb2.open(&held_back).unwrap(), b"y");
        let n2 = sb2.seal(b"back").unwrap();
        assert_eq!(&**sa2.open(&n2).unwrap(), b"back");
        let _ = (a, b);
    }

    #[test]
    fn damaged_session_bytes_are_refused() {
        let (_a, _b, sa, _sb) = established();
        let bytes = sa.to_bytes();
        for n in 0..bytes.len() {
            assert!(Session::from_bytes(&bytes[..n]).is_err(), "prefix {n}");
        }
        let mut bad = bytes.to_vec();
        bad[0] = 9;
        assert!(Session::from_bytes(&bad).is_err());
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert!(Session::from_bytes(&longer).is_err());
    }

    #[test]
    fn padding_uses_only_bucket_sizes_and_round_trips() {
        for len in [0usize, 1, 100, 511, 512, 513, 1000, 4096, 8191, 16383] {
            let data = vec![7u8; len];
            let p = pad(&data).unwrap();
            assert!(PAD_BUCKETS.contains(&p.len()), "len {len}");
            let mut back = p.to_vec();
            unpad(&mut back).unwrap();
            assert_eq!(back, data);
        }
        assert_eq!(pad(&vec![0u8; 16384]), Err(CryptoError::TooLarge));
        let mut odd = vec![1u8; 100];
        assert!(unpad(&mut odd).is_err());
        let mut no_marker = vec![0u8; 512];
        assert!(unpad(&mut no_marker).is_err());
    }

    #[test]
    fn ciphertext_lengths_show_only_the_bucket() {
        let (_a, _b, mut sa, _sb) = established();
        let short = sa.seal(b"hi").unwrap();
        let longer = sa.seal(&[b'x'; 300]).unwrap();
        assert_eq!(short.ciphertext.len(), longer.ciphertext.len());
        assert_eq!(short.ciphertext.len(), 512 + TAG_LEN);
    }

    #[test]
    fn envelope_decoder_rejects_every_truncation_and_bad_header() {
        let (_a, _b, mut sa, _sb) = established();
        let wire = sa.seal(b"abc").unwrap().encode();
        for n in 0..wire.len() {
            assert!(Envelope::decode(&wire[..n]).is_err(), "prefix {n}");
        }
        let mut longer = wire.clone();
        longer.push(0);
        assert!(Envelope::decode(&longer).is_err());
        let mut v = wire.clone();
        v[0] = 2;
        assert_eq!(Envelope::decode(&v), Err(CryptoError::Version(2)));
        let mut s = wire.clone();
        s[1] = 1;
        assert_eq!(Envelope::decode(&s), Err(CryptoError::Unsupported));
        // A declared length of 4 GiB must not be believed.
        let hdr = wire.len() - (512 + TAG_LEN) - 4;
        let mut huge = wire[..hdr].to_vec();
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(Envelope::decode(&huge).is_err());
    }

    #[test]
    fn a_low_order_public_key_is_refused() {
        // The identity point of Ed25519 is a weak key.
        let mut ident: [u8; 32] = rand::random();
        ident.fill(0);
        ident[0] = 1;
        assert!(peer_dh_public(&ident).is_err());
    }

    #[test]
    fn a_layered_message_needs_the_second_key_and_a_plain_one_still_opens() {
        let (_a, _b, mut sa, mut sb) = established();
        let k: [u8; 32] = rand::random();
        let other: [u8; 32] = rand::random();
        let m = sa.seal_with(b"layered", Some(&k)).unwrap();
        // The bytes have the shape of every other envelope.
        assert_eq!(Envelope::decode(&m.encode()).unwrap(), m);
        // Without the key, or with another one, it does not open and the
        // session is unchanged.
        assert!(sb.open(&m).is_err());
        assert!(sb.open_with(&m, Some(&other)).is_err());
        assert_eq!(&**sb.open_with(&m, Some(&k)).unwrap(), b"layered");
        // A receiver that holds the key still opens a message sent without it
        // (the sender may not have switched yet), in both orders.
        let plain = sa.seal(b"plain").unwrap();
        assert_eq!(&**sb.open_with(&plain, Some(&k)).unwrap(), b"plain");
        let m2 = sa.seal_with(b"again", Some(&k)).unwrap();
        let m3 = sa.seal(b"third").unwrap();
        assert_eq!(&**sb.open_with(&m3, Some(&k)).unwrap(), b"third");
        assert_eq!(&**sb.open_with(&m2, Some(&k)).unwrap(), b"again");
    }

    #[test]
    fn layered_messages_survive_a_reply_and_out_of_order_delivery() {
        let (_a, _b, mut sa, mut sb) = established();
        let k: [u8; 32] = rand::random();
        let old = sa.seal_with(b"old", Some(&k)).unwrap();
        let r = sb.seal_with(b"reply", Some(&k)).unwrap();
        assert_eq!(&**sa.open_with(&r, Some(&k)).unwrap(), b"reply");
        let new = sa.seal_with(b"new", Some(&k)).unwrap();
        // The new chain arrives first, the old message afterwards.
        assert_eq!(&**sb.open_with(&new, Some(&k)).unwrap(), b"new");
        assert_eq!(&**sb.open_with(&old, Some(&k)).unwrap(), b"old");
        // Tampering is still caught.
        let m = sa.seal_with(b"x", Some(&k)).unwrap();
        let mut bad = m.encode();
        let n = bad.len();
        bad[n - 1] ^= 1;
        let e = Envelope::decode(&bad).unwrap();
        assert!(sb.open_with(&e, Some(&k)).is_err());
        assert_eq!(&**sb.open_with(&m, Some(&k)).unwrap(), b"x");
    }

    #[test]
    fn file_stems_do_not_reveal_or_collide() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(file_stem(&a, &b), file_stem(&b, &a));
        assert_eq!(file_stem(&a, &b), file_stem(&a, &b));
        assert!(!file_stem(&a, &b).contains("0101"));
    }
}
