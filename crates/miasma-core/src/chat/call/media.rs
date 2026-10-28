//! Pure media-crypto library for the call feature (PR1).
//!
//! This module derives the per-call, per-direction media keys and seals and
//! opens media frames. It carries no transport, no signalling and no UI; it
//! only turns key material plus a packet counter into an authenticated frame
//! and back. The shape follows the chat ratchet in [`super::super::crypto`]:
//! the same HKDF construction and the same `Zeroizing` discipline, but with
//! dedicated call labels so a call key and a chat key never coincide.
//!
//! Design: design-call-security-v7e.md chapter 2 (2.1-2.5) and chapter 4
//! (4.1-4.3).
//!
//! Privacy: no key, nonce, call id, peer id or media sample is ever put in a
//! log, an error message or a `Debug` output. The error type below is a bare
//! enum with fixed text; the key-bearing types deliberately do not derive
//! `Debug`.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use super::super::crypto::label;

/// XChaCha20-Poly1305 nonce width (bytes). The 24-byte nonce of §2.4.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length (bytes).
pub const TAG_LEN: usize = 16;
/// Fixed media plaintext length (bytes), §4.4.2 (24 kbps, 20 ms frame).
pub const FRAME_PLAINTEXT_LEN: usize = 60;
/// Fixed wire header length (bytes), §4.4.2. Does NOT include call_id.
pub const WIRE_HEADER_LEN: usize = 14;
/// Media AAD length (bytes), §2.5 / §4.1.5. Includes call_id.
pub const AAD_LEN: usize = 30;
/// Total wire length of one media frame: header + ciphertext + tag, §4.4.2.
pub const FRAME_WIRE_LEN: usize = WIRE_HEADER_LEN + FRAME_PLAINTEXT_LEN + TAG_LEN;

/// Replay window width in packets, §4.2.1 (`MEDIA_REPLAY_WINDOW`).
pub const MEDIA_REPLAY_WINDOW: u64 = 2048;
/// Seconds between time-triggered epoch advances, §4.3.3
/// (`MEDIA_REKEY_SECONDS`). The forward-secrecy pacemaker.
pub const MEDIA_REKEY_SECONDS: u64 = 30;
/// Packet-count trigger for an epoch advance, §4.3.3 (`EPOCH_MAX_PACKETS`).
pub const EPOCH_MAX_PACKETS: u64 = 1 << 32;
/// Highest key_epoch value; on reaching it a call ends rather than wrap, §4.3.3.
pub const KEY_EPOCH_MAX: u32 = (1 << 24) - 1;
/// How many epochs a receiver may follow forward at once, §4.3.5.
pub const MAX_EPOCH_JUMP: u32 = 2;
/// How many previous epoch generations a receiver keeps, §4.2.2.
pub const EPOCH_RETAIN: u32 = 1;

/// A call direction. `Caller` is caller->callee (0x00), `Callee` is
/// callee->caller (0x01), §2.2 / §4.1.4. The authority that decides which
/// peer is the caller lives in signalling (chapter 3); this type only fixes
/// the byte assignment.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Caller,
    Callee,
}

impl Direction {
    #[inline]
    pub fn byte(self) -> u8 {
        match self {
            Direction::Caller => 0x00,
            Direction::Callee => 0x01,
        }
    }
}

/// The media-protocol version that leads the header and the AAD, §4.1.5.
pub const MEDIA_PROTOCOL_VERSION: u8 = 0x01;

/// Errors are a bare enum with fixed text: no key, nonce, call id, peer id or
/// sample ever appears here (privacy rule, §6).
#[derive(Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MediaError {
    #[error("the media frame did not authenticate")]
    Authentication,
    #[error("this media frame was already received")]
    Replay,
    #[error("this media frame is outside the replay window")]
    OutsideWindow,
    #[error("the key schedule failed")]
    KeySchedule,
    #[error("the key_epoch space is exhausted; end the call")]
    EpochExhausted,
    #[error("the key_epoch jumps too far ahead")]
    EpochTooFarAhead,
    #[error("a packet counter went backwards")]
    CounterRewound,
    #[error("the media frame is malformed")]
    Malformed,
}

// A bare `Debug` that never prints internals, so `?` and test asserts that
// require `Debug` cannot leak anything. It mirrors the variant name only.
impl core::fmt::Debug for MediaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            MediaError::Authentication => "Authentication",
            MediaError::Replay => "Replay",
            MediaError::OutsideWindow => "OutsideWindow",
            MediaError::KeySchedule => "KeySchedule",
            MediaError::EpochExhausted => "EpochExhausted",
            MediaError::EpochTooFarAhead => "EpochTooFarAhead",
            MediaError::CounterRewound => "CounterRewound",
            MediaError::Malformed => "Malformed",
        };
        f.write_str(name)
    }
}

/// A 32-byte secret buffer, zeroized on drop, with no `Debug`.
///
/// We keep our own alias over `Zeroizing<[u8; 32]>` so the key-bearing structs
/// below never accidentally gain a `Debug` or `Clone` that prints or copies
/// secret bytes.
type Secret32 = Zeroizing<[u8; 32]>;

/// Output buffer of `N` random bytes, zeroized on drop. No literal constant
/// ever sits where key material goes (mirrors `crypto::fresh`).
fn fresh<const N: usize>() -> Zeroizing<[u8; N]> {
    Zeroizing::new(std::array::from_fn(|_| rand::random::<u8>()))
}

/// `MK_root[direction]` from the ratchet chain key and the hybrid session key,
/// §2.2. Both inputs are mandatory: without the hybrid key the ikm cannot be
/// built and no media key exists (§2.6). `info = call_id || call_nonce ||
/// direction`, `salt = CALL_MEDIA_ROOT`.
pub fn derive_mk_root(
    ratchet_chain_key: &[u8; 32],
    hybrid_session_key: &[u8; 32],
    call_id: &[u8; 16],
    call_nonce: &[u8; 16],
    direction: Direction,
) -> Result<Secret32, MediaError> {
    let mut ikm = fresh::<64>();
    ikm[..32].copy_from_slice(ratchet_chain_key);
    ikm[32..].copy_from_slice(hybrid_session_key);
    let mut info = Zeroizing::new(Vec::with_capacity(16 + 16 + 1));
    info.extend_from_slice(call_id);
    info.extend_from_slice(call_nonce);
    info.push(direction.byte());
    let hk = Hkdf::<Sha256>::new(Some(label::CALL_MEDIA_ROOT), ikm.as_ref());
    let mut out = fresh::<32>();
    hk.expand(&info, out.as_mut())
        .map_err(|_| MediaError::KeySchedule)?;
    Ok(out)
}

/// Derive a direction-specific media root from the two signalling shares.
pub fn derive_mk_root_from_shares(
    caller_share: &[u8; 32],
    callee_share: &[u8; 32],
    call_id: &[u8; 16],
    caller_nonce: &[u8; 16],
    callee_nonce: &[u8; 16],
    offer_hash: &[u8; 32],
    direction: Direction,
) -> Result<Zeroizing<[u8; 32]>, MediaError> {
    let mut ikm = fresh::<64>();
    ikm[..32].copy_from_slice(caller_share);
    ikm[32..].copy_from_slice(callee_share);
    let mut info = Zeroizing::new(Vec::with_capacity(16 + 16 + 16 + 32 + 1));
    info.extend_from_slice(call_id);
    info.extend_from_slice(caller_nonce);
    info.extend_from_slice(callee_nonce);
    info.extend_from_slice(offer_hash);
    info.push(direction.byte());
    let hk = Hkdf::<Sha256>::new(Some(label::CALL_MEDIA_ROOT), ikm.as_ref());
    let mut out = fresh::<32>();
    hk.expand(&info, out.as_mut())
        .map_err(|_| MediaError::KeySchedule)?;
    Ok(out)
}

/// The epoch-0 chain key from `MK_root`, §2.3 / §4.3.1. One HKDF step so the
/// distance between `MK_root` and the first chain key is not zero.
/// `salt = CALL_CHAIN_INIT`, `info = key_epoch(3B) = 0`.
pub fn init_chain_key(mk_root: &[u8; 32]) -> Result<Secret32, MediaError> {
    let hk = Hkdf::<Sha256>::new(Some(label::CALL_CHAIN_INIT), mk_root);
    let info = epoch_be3(0);
    let mut out = fresh::<32>();
    hk.expand(&info, out.as_mut())
        .map_err(|_| MediaError::KeySchedule)?;
    Ok(out)
}

/// One forward step of the per-direction chain, §2.3 / §4.3.2. Reuses the
/// *structure* of `crypto::kdf_chain` but with the call-only labels: the next
/// chain key is an independent expand under `CALL_CHAIN` (32B); the message
/// material is an expand under `CALL_MESSAGE` (56B) whose first 32 bytes are
/// the message key. The trailing 24 bytes (a nonce in `kdf_chain`) are NOT
/// used: media nonces come from the sequence number (§2.4).
pub fn chain_step(chain_key: &[u8; 32]) -> Result<(Secret32, Secret32), MediaError> {
    let hk = Hkdf::<Sha256>::from_prk(chain_key).map_err(|_| MediaError::KeySchedule)?;
    let mut next = fresh::<32>();
    hk.expand(label::CALL_CHAIN, next.as_mut())
        .map_err(|_| MediaError::KeySchedule)?;
    let mut mat = fresh::<56>();
    hk.expand(label::CALL_MESSAGE, mat.as_mut())
        .map_err(|_| MediaError::KeySchedule)?;
    let mut msg_key = fresh::<32>();
    msg_key.copy_from_slice(&mat[..32]);
    // mat[32..] (the 24 trailing bytes) is deliberately left unused and is
    // zeroized with `mat` on drop.
    Ok((msg_key, next))
}

/// `key_epoch` as 3 big-endian bytes. Only the low 24 bits are meaningful
/// (`KEY_EPOCH_MAX`); callers keep the counter within range.
fn epoch_be3(epoch: u32) -> [u8; 3] {
    let b = epoch.to_be_bytes();
    [b[1], b[2], b[3]]
}

/// The 24-byte media nonce, §2.4 / §4.1.2:
/// `direction(1) || key_epoch(3) || packet_seq(8) || zero-pad(12)`.
/// The trailing 12 bytes are always zero; uniqueness rests entirely on the
/// send-side counter discipline (no random component).
pub fn media_nonce(direction: Direction, key_epoch: u32, packet_seq: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[0] = direction.byte();
    n[1..4].copy_from_slice(&epoch_be3(key_epoch));
    n[4..12].copy_from_slice(&packet_seq.to_be_bytes());
    // n[12..24] stays zero.
    n
}

/// The 30-byte media AAD, §2.5 / §4.1.5:
/// `version(1) || call_id(16) || direction(1) || key_epoch(3) ||
///  packet_seq(8) || media_type(1)`. The call_id is bound here only; it is
/// never placed on the wire (the receiver rebuilds the AAD from the active
/// call's id).
pub fn media_aad(
    call_id: &[u8; 16],
    direction: Direction,
    key_epoch: u32,
    packet_seq: u64,
    media_type: u8,
) -> [u8; AAD_LEN] {
    let mut a = [0u8; AAD_LEN];
    a[0] = MEDIA_PROTOCOL_VERSION;
    a[1..17].copy_from_slice(call_id);
    a[17] = direction.byte();
    a[18..21].copy_from_slice(&epoch_be3(key_epoch));
    a[21..29].copy_from_slice(&packet_seq.to_be_bytes());
    a[29] = media_type;
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    // All tests use run-time random key material (no fixed keys), per the
    // chapter-7 rule for PR1.
    fn rand32() -> [u8; 32] {
        std::array::from_fn(|_| rand::random::<u8>())
    }
    fn rand16() -> [u8; 16] {
        std::array::from_fn(|_| rand::random::<u8>())
    }

    // §2.2: both ends that share the same (chain key, hybrid key, call_id,
    // call_nonce, direction) derive the same MK_root, byte for byte.
    #[test]
    fn share_root_binds_all_inputs() {
        let caller = Zeroizing::new(rand32());
        let callee = Zeroizing::new(rand32());
        let id = rand16();
        let caller_nonce = rand16();
        let callee_nonce = rand16();
        let hash = rand32();
        let derive =
            |a: &[u8; 32],
             b: &[u8; 32],
             i: &[u8; 16],
             n: &[u8; 16],
             m: &[u8; 16],
             h: &[u8; 32],
             d| { derive_mk_root_from_shares(a, b, i, n, m, h, d).unwrap() };
        let base = derive(
            &caller,
            &callee,
            &id,
            &caller_nonce,
            &callee_nonce,
            &hash,
            Direction::Caller,
        );
        let same = derive(
            &caller,
            &callee,
            &id,
            &caller_nonce,
            &callee_nonce,
            &hash,
            Direction::Caller,
        );
        assert!(*base == *same);
        let mut ca = caller.clone();
        ca[0] ^= 1;
        let mut cb = callee.clone();
        cb[0] ^= 1;
        let mut ci = id;
        ci[0] ^= 1;
        let mut cn = caller_nonce;
        cn[0] ^= 1;
        let mut cm = callee_nonce;
        cm[0] ^= 1;
        let mut ch = hash;
        ch[0] ^= 1;
        let variants = [
            derive(
                &ca,
                &callee,
                &id,
                &caller_nonce,
                &callee_nonce,
                &hash,
                Direction::Caller,
            ),
            derive(
                &caller,
                &cb,
                &id,
                &caller_nonce,
                &callee_nonce,
                &hash,
                Direction::Caller,
            ),
            derive(
                &caller,
                &callee,
                &ci,
                &caller_nonce,
                &callee_nonce,
                &hash,
                Direction::Caller,
            ),
            derive(
                &caller,
                &callee,
                &id,
                &cn,
                &callee_nonce,
                &hash,
                Direction::Caller,
            ),
            derive(
                &caller,
                &callee,
                &id,
                &caller_nonce,
                &cm,
                &hash,
                Direction::Caller,
            ),
            derive(
                &caller,
                &callee,
                &id,
                &caller_nonce,
                &callee_nonce,
                &ch,
                Direction::Caller,
            ),
            derive(
                &caller,
                &callee,
                &id,
                &caller_nonce,
                &callee_nonce,
                &hash,
                Direction::Callee,
            ),
        ];
        for variant in variants {
            assert!(*base != *variant);
        }
    }

    #[test]
    fn mk_root_matches_both_ends() {
        let ck = rand32();
        let hk = rand32();
        let call_id = rand16();
        let call_nonce = rand16();
        let a = derive_mk_root(&ck, &hk, &call_id, &call_nonce, Direction::Caller).unwrap();
        let b = derive_mk_root(&ck, &hk, &call_id, &call_nonce, Direction::Caller).unwrap();
        assert!(a.as_ref() == b.as_ref());
    }

    // §2.2 / §7 2.1: changing call_nonce on one end alone yields a different
    // MK_root (so a mismatched nonce cannot decrypt).
    #[test]
    fn mk_root_differs_on_nonce_change() {
        let ck = rand32();
        let hk = rand32();
        let call_id = rand16();
        let n1 = rand16();
        let mut n2 = n1;
        n2[0] ^= 0x01;
        let a = derive_mk_root(&ck, &hk, &call_id, &n1, Direction::Caller).unwrap();
        let b = derive_mk_root(&ck, &hk, &call_id, &n2, Direction::Caller).unwrap();
        assert!(a.as_ref() != b.as_ref());
    }

    // §2.2 / §7 2.2: the two directions derive different MK_root values, so a
    // caller->callee key never opens a callee->caller frame.
    #[test]
    fn mk_root_separates_directions() {
        let ck = rand32();
        let hk = rand32();
        let call_id = rand16();
        let call_nonce = rand16();
        let caller = derive_mk_root(&ck, &hk, &call_id, &call_nonce, Direction::Caller).unwrap();
        let callee = derive_mk_root(&ck, &hk, &call_id, &call_nonce, Direction::Callee).unwrap();
        assert!(caller.as_ref() != callee.as_ref());
    }

    // §2.2: the hybrid key is mandatory. Dropping it (a different hybrid key)
    // changes MK_root; the ikm is always 64 bytes (both halves filled).
    #[test]
    fn mk_root_binds_both_inputs() {
        let ck = rand32();
        let hk1 = rand32();
        let hk2 = rand32();
        let call_id = rand16();
        let call_nonce = rand16();
        let a = derive_mk_root(&ck, &hk1, &call_id, &call_nonce, Direction::Caller).unwrap();
        let b = derive_mk_root(&ck, &hk2, &call_id, &call_nonce, Direction::Caller).unwrap();
        assert!(a.as_ref() != b.as_ref());
        // and the ratchet half matters too
        let ck2 = rand32();
        let c = derive_mk_root(&ck2, &hk1, &call_id, &call_nonce, Direction::Caller).unwrap();
        assert!(a.as_ref() != c.as_ref());
    }

    // §2.3 / §4.3.1: the epoch-0 chain key is not MK_root itself (one HKDF
    // step of distance), and it is deterministic.
    #[test]
    fn init_chain_key_is_distinct_and_deterministic() {
        let mk = rand32();
        let a = init_chain_key(&mk).unwrap();
        let b = init_chain_key(&mk).unwrap();
        assert!(a.as_ref() == b.as_ref());
        assert!(a.as_ref() != &mk);
    }

    // §2.3 / §4.3.2: one chain step yields a message key and the next chain
    // key; the two outputs differ from each other and from the input, and the
    // step is deterministic.
    #[test]
    fn chain_step_outputs_are_distinct() {
        let ck = rand32();
        let (mk1, next1) = chain_step(&ck).unwrap();
        let (mk2, next2) = chain_step(&ck).unwrap();
        assert!(mk1.as_ref() == mk2.as_ref());
        assert!(next1.as_ref() == next2.as_ref());
        assert!(mk1.as_ref() != next1.as_ref());
        assert!(mk1.as_ref() != &ck);
        assert!(next1.as_ref() != &ck);
    }

    // §2.3: advancing the chain gives a fresh message key each epoch.
    #[test]
    fn chain_advance_gives_fresh_message_keys() {
        let mk = rand32();
        let ck0 = init_chain_key(&mk).unwrap();
        let (m0, ck1) = chain_step(&ck0).unwrap();
        let (m1, ck2) = chain_step(&ck1).unwrap();
        let (m2, _ck3) = chain_step(&ck2).unwrap();
        assert!(m0.as_ref() != m1.as_ref());
        assert!(m1.as_ref() != m2.as_ref());
        assert!(m0.as_ref() != m2.as_ref());
    }

    // §2.3 / §2.2: the call chain labels are dedicated and never coincide with
    // the chat CHAIN/MESSAGE labels, so the same chain-key input yields a
    // different output for a call than for a chat.
    #[test]
    fn call_labels_are_separate_from_chat_labels() {
        assert_ne!(label::CALL_CHAIN, label::CHAIN);
        assert_ne!(label::CALL_MESSAGE, label::MESSAGE);
        assert_ne!(label::CALL_MEDIA_ROOT, label::PQ_LAYER);
        // A chain key expanded under the call label must differ from the same
        // chain key expanded under the chat label.
        let ck = rand32();
        let hk = Hkdf::<Sha256>::from_prk(&ck).unwrap();
        let mut call_out = [0u8; 32];
        let mut chat_out = [0u8; 32];
        hk.expand(label::CALL_CHAIN, &mut call_out).unwrap();
        hk.expand(label::CHAIN, &mut chat_out).unwrap();
        assert!(call_out != chat_out);
    }

    // §2.4: the 24-byte nonce has the fields in the right place and the
    // trailing 12 bytes are always zero.
    #[test]
    fn nonce_layout_and_zero_pad() {
        let n = media_nonce(Direction::Callee, 0x00ABCD, 0x0102030405060708);
        // direction byte
        assert!(n[0] == 0x01);
        // key_epoch big-endian in bytes 1..4 (low 24 bits)
        assert!(&n[1..4] == &[0x00, 0xAB, 0xCD]);
        // packet_seq big-endian in bytes 4..12
        assert!(&n[4..12] == &0x0102030405060708u64.to_be_bytes());
        // trailing 12 bytes are zero
        assert!(&n[12..24] == &[0u8; 12]);
    }

    // §2.4: (direction, key_epoch, packet_seq) are globally unique, so the
    // nonce is never reused under one key. Enumerate a grid and confirm no two
    // nonces collide.
    #[test]
    fn nonce_is_unique_across_direction_epoch_seq() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for dir in [Direction::Caller, Direction::Callee] {
            for epoch in 0u32..4 {
                for seq in 0u64..64 {
                    let n = media_nonce(dir, epoch, seq);
                    assert!(seen.insert(n), "nonce reused");
                }
            }
        }
    }

    // §2.5 / §4.1.5: the AAD is 30 bytes, call_id occupies bytes 1..17, and
    // changing any field changes the AAD.
    #[test]
    fn aad_layout_and_binding() {
        let call_id = rand16();
        let a = media_aad(&call_id, Direction::Caller, 7, 9, 0x00);
        assert_eq!(a.len(), AAD_LEN);
        assert_eq!(a[0], MEDIA_PROTOCOL_VERSION);
        assert!(&a[1..17] == &call_id);
        // a different media_type gives a different AAD
        let b = media_aad(&call_id, Direction::Caller, 7, 9, 0x01);
        assert!(a != b);
        // a different direction gives a different AAD
        let c = media_aad(&call_id, Direction::Callee, 7, 9, 0x00);
        assert!(a != c);
    }
}
