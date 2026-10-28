//! Call signalling records and their strict binary codec (PR2a).
//!
//! This module defines the call-control record kinds and encodes/decodes their
//! bodies. These records are **not** the envelope wire kind: the envelope wire
//! kind stays `KIND_PAIR = 1` (see [`super::super::crypto`]); a call record kind
//! is the first byte of the DECRYPTED envelope body, in the unused band
//! `0x30..=0x37`, beside the hybrid handshake kinds `0x20..=0x23`
//! ([`super::super::pq`]). Design: design-call-security-v7e.md chapter 3,
//! sections 3.1 (kinds) and 3.2 (body fields and binding).
//!
//! Scope: only the record kinds and their strict binary codec. No state
//! machine, no outbox, no IPC, no UI, no transport. The strict-decoder style
//! follows the chat envelope decoder in [`super::super::crypto`]: fixed-width
//! fields read in order, a length prefix for the variable part, unknown kinds
//! and unknown reason codes rejected, trailing bytes rejected, and never a
//! panic on hostile input.
//!
//! Privacy (§6): no secret, key, nonce, call id, peer id or media sample is put
//! in any log, error text or `Debug` output. `call_id` and `call_nonce` are not
//! secrets, but to keep callers from printing them by accident the carrier
//! types deliberately do not derive `Debug`, and the error type below is a bare
//! enum with fixed text.

use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::super::crypto::Rd;

/// Length of a call id (bytes), §3.2.1.
pub const CALL_ID_LEN: usize = 16;
/// Length of a call nonce (bytes), §3.2.1.
pub const CALL_NONCE_LEN: usize = 16;
/// Length of a media key share (bytes).
pub const KEY_SHARE_LEN: usize = 32;
/// Length of an offer hash (bytes): SHA-256 of the whole offer body, §2.7.6.
pub const OFFER_HASH_LEN: usize = 32;

/// Default time-to-live of a call offer (seconds), §3.2.1.
pub const CALL_TTL_SECONDS_DEFAULT: u64 = 45;
/// Lowest configurable offer TTL (seconds), §3.2.1.
pub const CALL_TTL_SECONDS_MIN: u64 = 30;
/// Highest configurable offer TTL (seconds), §3.2.1.
pub const CALL_TTL_SECONDS_MAX: u64 = 60;

/// Upper bound on a decoded capability field, so a hostile length prefix cannot
/// ask us to size a huge buffer. The capability block is small (codec/CBR/DTX
/// flags); a few hundred bytes is already generous.
pub(super) const MAX_CAPABILITIES_LEN: usize = 1024;

/// Reason codes carried by reject/busy/cancel records, §3.1.2.
///
/// These are the stable wire values. `busy` always rides a `CALL_BUSY` record;
/// the gate-derived reasons (`pqc_failed`, `pqc_peer_no_hybrid`) copy the stable
/// strings from `PqcRefusal::reason_str()` without ever carrying a peer id.
pub mod reason {
    pub const NOT_CONTACT: u8 = 0x00;
    pub const BUSY: u8 = 0x01;
    pub const DECLINED: u8 = 0x02;
    pub const CANCELED: u8 = 0x03;
    pub const TIMEOUT: u8 = 0x04;
    pub const GATE_UNDECIDED: u8 = 0x05;
    pub const PQC_FAILED: u8 = 0x06;
    pub const PQC_PEER_NO_HYBRID: u8 = 0x07;
    pub const COLLISION_LOST: u8 = 0x08;

    /// True for a reason code this codec understands. Anything else is rejected
    /// by the decoder (reject unknown fields).
    pub fn is_known(r: u8) -> bool {
        (NOT_CONTACT..=COLLISION_LOST).contains(&r)
    }
}

/// Call-control record kinds, §3.1.2. Carried as the first byte of the decrypted
/// envelope body, in the unused band `0x30..=0x37`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `0x30` caller->callee: begin a call.
    Offer,
    /// `0x31` callee->caller: accept a call.
    Answer,
    /// `0x32` callee->caller: decline a call.
    Reject,
    /// `0x33` callee->caller: busy with another call.
    Busy,
    /// `0x34` caller->callee: withdraw a pending offer.
    Cancel,
    /// `0x35` either side: hang up an established call.
    Bye,
    /// `0x36` either side: delivery acknowledgement (no state change).
    Ack,
    /// `0x37` caller->caller: simultaneous-offer collision notice.
    Collide,
}

/// A bare `Debug` that prints only the variant name. A record kind is not
/// secret, but keeping `Debug` free of any field value keeps the whole module's
/// `?`/assert surface leak-proof.
impl core::fmt::Debug for Kind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Kind::Offer => "Offer",
            Kind::Answer => "Answer",
            Kind::Reject => "Reject",
            Kind::Busy => "Busy",
            Kind::Cancel => "Cancel",
            Kind::Bye => "Bye",
            Kind::Ack => "Ack",
            Kind::Collide => "Collide",
        })
    }
}

impl Kind {
    /// The wire byte for this kind (first byte of the decrypted body), §3.1.2.
    #[inline]
    pub fn byte(self) -> u8 {
        match self {
            Kind::Offer => 0x30,
            Kind::Answer => 0x31,
            Kind::Reject => 0x32,
            Kind::Busy => 0x33,
            Kind::Cancel => 0x34,
            Kind::Bye => 0x35,
            Kind::Ack => 0x36,
            Kind::Collide => 0x37,
        }
    }

    /// Parse a kind byte. Unknown bytes (including the hybrid band `0x20..=0x23`
    /// and anything outside `0x30..=0x37`) return `None`; the caller rejects
    /// them cleanly so a peer that does not know this protocol is refused
    /// without disturbing chat.
    #[inline]
    pub fn from_byte(b: u8) -> Option<Kind> {
        Some(match b {
            0x30 => Kind::Offer,
            0x31 => Kind::Answer,
            0x32 => Kind::Reject,
            0x33 => Kind::Busy,
            0x34 => Kind::Cancel,
            0x35 => Kind::Bye,
            0x36 => Kind::Ack,
            0x37 => Kind::Collide,
            _ => return None,
        })
    }

    /// True for any byte in the call signalling band `0x30..=0x37`.
    #[inline]
    pub fn is_signal_kind(b: u8) -> bool {
        (0x30..=0x37).contains(&b)
    }
}

/// A decoded call signalling record, §3.1.2 / §3.2.1.
///
/// One variant per kind. Fields are the exact body values that must be present
/// (§3.2): `call_id` (16 bytes), `call_nonce` (16 bytes), `created_at` and
/// `expires_at` in milliseconds, a `reason` code, the echoed call id for
/// collision, the capability block whose SHA-256 is the `offer_hash`, and the
/// acked kind for `Ack`.
///
/// No `Debug`/`Clone` is derived so a `call_id`/`call_nonce` never prints by
/// accident; use [`Record::kind`] and the field accessors when a test needs to
/// compare values.
pub enum Record {
    Offer {
        call_id: [u8; CALL_ID_LEN],
        call_nonce: [u8; CALL_NONCE_LEN],
        key_share: Zeroizing<[u8; KEY_SHARE_LEN]>,
        created_at_ms: u64,
        expires_at_ms: u64,
        /// Media capability block (codec/CBR/DTX/direction). Its SHA-256 over
        /// the whole encoded body is the `offer_hash` bound into the SAS
        /// (§2.7.6); the internals are owned by chapter 4 and treated here as
        /// opaque length-prefixed bytes.
        capabilities: Vec<u8>,
    },
    Answer {
        call_id: [u8; CALL_ID_LEN],
        call_nonce: [u8; CALL_NONCE_LEN],
        key_share: Zeroizing<[u8; KEY_SHARE_LEN]>,
        created_at_ms: u64,
        capabilities: Vec<u8>,
    },
    Reject {
        call_id: [u8; CALL_ID_LEN],
        created_at_ms: u64,
        reason: u8,
    },
    Busy {
        call_id: [u8; CALL_ID_LEN],
        created_at_ms: u64,
        reason: u8,
    },
    Cancel {
        call_id: [u8; CALL_ID_LEN],
        created_at_ms: u64,
        reason: u8,
    },
    Bye {
        call_id: [u8; CALL_ID_LEN],
        created_at_ms: u64,
    },
    Ack {
        call_id: [u8; CALL_ID_LEN],
        /// The kind byte this record acknowledges.
        acked_kind: u8,
    },
    Collide {
        call_id: [u8; CALL_ID_LEN],
        peer_call_id: [u8; CALL_ID_LEN],
        created_at_ms: u64,
    },
}

/// A bare error enum with fixed text: no field value, no secret ever appears.
/// Distinct from `crypto::CryptoError` so the signalling codec can be tested in
/// isolation.
#[derive(Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignalError {
    /// The first byte is not a call signalling kind (`0x30..=0x37`).
    #[error("unknown call record kind")]
    UnknownKind,
    /// A reason code is not one this codec understands.
    #[error("unknown reason code")]
    UnknownReason,
    /// The body ended before all required fields were read.
    #[error("the call record was truncated")]
    Truncated,
    /// A length prefix asked for more than the fixed maximum.
    #[error("a length prefix is too large")]
    Oversized,
    /// Bytes remained after the record was fully decoded.
    #[error("the call record had trailing bytes")]
    TrailingBytes,
    /// A variable field is longer than the fixed maximum it may encode to.
    #[error("a signalling field is too long to encode")]
    TooLong,
}

impl core::fmt::Debug for SignalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            SignalError::UnknownKind => "UnknownKind",
            SignalError::UnknownReason => "UnknownReason",
            SignalError::Truncated => "Truncated",
            SignalError::Oversized => "Oversized",
            SignalError::TrailingBytes => "TrailingBytes",
            SignalError::TooLong => "TooLong",
        })
    }
}

impl Record {
    /// The kind of this record.
    pub fn kind(&self) -> Kind {
        match self {
            Record::Offer { .. } => Kind::Offer,
            Record::Answer { .. } => Kind::Answer,
            Record::Reject { .. } => Kind::Reject,
            Record::Busy { .. } => Kind::Busy,
            Record::Cancel { .. } => Kind::Cancel,
            Record::Bye { .. } => Kind::Bye,
            Record::Ack { .. } => Kind::Ack,
            Record::Collide { .. } => Kind::Collide,
        }
    }

    /// The call id this record is bound to (the primary call id for `Collide`).
    pub fn call_id(&self) -> &[u8; CALL_ID_LEN] {
        match self {
            Record::Offer { call_id, .. }
            | Record::Answer { call_id, .. }
            | Record::Reject { call_id, .. }
            | Record::Busy { call_id, .. }
            | Record::Cancel { call_id, .. }
            | Record::Bye { call_id, .. }
            | Record::Ack { call_id, .. }
            | Record::Collide { call_id, .. } => call_id,
        }
    }

    /// Encode this record to its on-the-wire body: the kind byte followed by the
    /// fixed-width fields in order, with a 2-byte length prefix for the variable
    /// capability block. This is the plaintext that the envelope AEAD seals; the
    /// envelope wire kind stays `KIND_PAIR`.
    ///
    /// Returns [`SignalError::TooLong`] if a capability block exceeds
    /// [`MAX_CAPABILITIES_LEN`], the largest length the 2-byte prefix may carry
    /// here; a valid record always encodes.
    pub fn encode(&self) -> Result<Vec<u8>, SignalError> {
        let capacity = match self {
            Record::Offer { capabilities, .. } | Record::Answer { capabilities, .. } => {
                if capabilities.len() > MAX_CAPABILITIES_LEN {
                    return Err(SignalError::TooLong);
                }
                1 + CALL_ID_LEN + CALL_NONCE_LEN + KEY_SHARE_LEN + 16 + 2 + capabilities.len()
            }
            _ => 64,
        };
        let mut v = Vec::with_capacity(capacity);
        v.push(self.kind().byte());
        match self {
            Record::Offer {
                call_id,
                call_nonce,
                key_share,
                created_at_ms,
                expires_at_ms,
                capabilities,
            } => {
                v.extend_from_slice(call_id);
                v.extend_from_slice(call_nonce);
                v.extend_from_slice(key_share.as_ref());
                v.extend_from_slice(&created_at_ms.to_be_bytes());
                v.extend_from_slice(&expires_at_ms.to_be_bytes());
                put_lp(&mut v, capabilities)?;
            }
            Record::Answer {
                call_id,
                call_nonce,
                key_share,
                created_at_ms,
                capabilities,
            } => {
                v.extend_from_slice(call_id);
                v.extend_from_slice(call_nonce);
                v.extend_from_slice(key_share.as_ref());
                v.extend_from_slice(&created_at_ms.to_be_bytes());
                put_lp(&mut v, capabilities)?;
            }
            Record::Reject {
                call_id,
                created_at_ms,
                reason,
            }
            | Record::Busy {
                call_id,
                created_at_ms,
                reason,
            }
            | Record::Cancel {
                call_id,
                created_at_ms,
                reason,
            } => {
                v.extend_from_slice(call_id);
                v.extend_from_slice(&created_at_ms.to_be_bytes());
                v.push(*reason);
            }
            Record::Bye {
                call_id,
                created_at_ms,
            } => {
                v.extend_from_slice(call_id);
                v.extend_from_slice(&created_at_ms.to_be_bytes());
            }
            Record::Ack {
                call_id,
                acked_kind,
            } => {
                v.extend_from_slice(call_id);
                v.push(*acked_kind);
            }
            Record::Collide {
                call_id,
                peer_call_id,
                created_at_ms,
            } => {
                v.extend_from_slice(call_id);
                v.extend_from_slice(peer_call_id);
                v.extend_from_slice(&created_at_ms.to_be_bytes());
            }
        }
        Ok(v)
    }

    /// Encode into a buffer that is cleared when dropped.
    pub fn encode_zeroizing(&self) -> Result<Zeroizing<Vec<u8>>, SignalError> {
        self.encode().map(Zeroizing::new)
    }

    /// Strict decoder. Reads the kind byte, then the fixed-width fields in order,
    /// then the length-prefixed variable part; rejects unknown kinds, unknown
    /// reason codes, oversized length prefixes and trailing bytes; and never
    /// panics on hostile input (every read is bounds-checked by [`Rd`]).
    pub fn decode(b: &[u8]) -> Result<Record, SignalError> {
        let mut r = Rd::new(b);
        let kind_byte = r.u8().map_err(|_| SignalError::Truncated)?;
        let kind = Kind::from_byte(kind_byte).ok_or(SignalError::UnknownKind)?;

        let rec = match kind {
            Kind::Offer => {
                let call_id = r.arr::<CALL_ID_LEN>().map_err(|_| SignalError::Truncated)?;
                let call_nonce = r
                    .arr::<CALL_NONCE_LEN>()
                    .map_err(|_| SignalError::Truncated)?;
                let key_share = Zeroizing::new(
                    r.arr::<KEY_SHARE_LEN>()
                        .map_err(|_| SignalError::Truncated)?,
                );
                let created_at_ms = r.u64().map_err(|_| SignalError::Truncated)?;
                let expires_at_ms = r.u64().map_err(|_| SignalError::Truncated)?;
                let capabilities = take_lp(&mut r)?;
                Record::Offer {
                    call_id,
                    call_nonce,
                    key_share,
                    created_at_ms,
                    expires_at_ms,
                    capabilities,
                }
            }
            Kind::Answer => {
                let call_id = r.arr::<CALL_ID_LEN>().map_err(|_| SignalError::Truncated)?;
                let call_nonce = r
                    .arr::<CALL_NONCE_LEN>()
                    .map_err(|_| SignalError::Truncated)?;
                let key_share = Zeroizing::new(
                    r.arr::<KEY_SHARE_LEN>()
                        .map_err(|_| SignalError::Truncated)?,
                );
                let created_at_ms = r.u64().map_err(|_| SignalError::Truncated)?;
                let capabilities = take_lp(&mut r)?;
                Record::Answer {
                    call_id,
                    call_nonce,
                    key_share,
                    created_at_ms,
                    capabilities,
                }
            }
            Kind::Reject | Kind::Busy | Kind::Cancel => {
                let call_id = r.arr::<CALL_ID_LEN>().map_err(|_| SignalError::Truncated)?;
                let created_at_ms = r.u64().map_err(|_| SignalError::Truncated)?;
                let reason = r.u8().map_err(|_| SignalError::Truncated)?;
                if !reason::is_known(reason) {
                    return Err(SignalError::UnknownReason);
                }
                match kind {
                    Kind::Reject => Record::Reject {
                        call_id,
                        created_at_ms,
                        reason,
                    },
                    Kind::Busy => Record::Busy {
                        call_id,
                        created_at_ms,
                        reason,
                    },
                    _ => Record::Cancel {
                        call_id,
                        created_at_ms,
                        reason,
                    },
                }
            }
            Kind::Bye => {
                let call_id = r.arr::<CALL_ID_LEN>().map_err(|_| SignalError::Truncated)?;
                let created_at_ms = r.u64().map_err(|_| SignalError::Truncated)?;
                Record::Bye {
                    call_id,
                    created_at_ms,
                }
            }
            Kind::Ack => {
                let call_id = r.arr::<CALL_ID_LEN>().map_err(|_| SignalError::Truncated)?;
                let acked_kind = r.u8().map_err(|_| SignalError::Truncated)?;
                // The acked kind must itself be a defined signalling kind;
                // reject any other byte the way an unknown record kind is.
                if Kind::from_byte(acked_kind).is_none() {
                    return Err(SignalError::UnknownKind);
                }
                Record::Ack {
                    call_id,
                    acked_kind,
                }
            }
            Kind::Collide => {
                let call_id = r.arr::<CALL_ID_LEN>().map_err(|_| SignalError::Truncated)?;
                let peer_call_id = r.arr::<CALL_ID_LEN>().map_err(|_| SignalError::Truncated)?;
                let created_at_ms = r.u64().map_err(|_| SignalError::Truncated)?;
                Record::Collide {
                    call_id,
                    peer_call_id,
                    created_at_ms,
                }
            }
        };

        if !r.done() {
            return Err(SignalError::TrailingBytes);
        }
        Ok(rec)
    }
}

/// Write a 2-byte big-endian length prefix and then the bytes. Rejects a block
/// longer than [`MAX_CAPABILITIES_LEN`] with [`SignalError::TooLong`] so an
/// over-long block can never truncate into the 2-byte prefix and corrupt the
/// frame; the decoder enforces the same bound.
fn put_lp(v: &mut Vec<u8>, bytes: &[u8]) -> Result<(), SignalError> {
    if bytes.len() > MAX_CAPABILITIES_LEN {
        return Err(SignalError::TooLong);
    }
    v.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    v.extend_from_slice(bytes);
    Ok(())
}

/// Read a 2-byte length prefix and that many bytes, rejecting an oversized
/// prefix before anything is sized and a short body as truncation.
fn take_lp(r: &mut Rd<'_>) -> Result<Vec<u8>, SignalError> {
    let n = r.u16().map_err(|_| SignalError::Truncated)? as usize;
    if n > MAX_CAPABILITIES_LEN {
        return Err(SignalError::Oversized);
    }
    let bytes = r.bytes(n).map_err(|_| SignalError::Truncated)?;
    Ok(bytes.to_vec())
}

/// A fresh 16-byte call id drawn straight from the OS random source, §3.2.1.
///
/// Uses `OsRng` directly (not the `fresh()` KDF-output helper); call ids are
/// public identifiers, not KDF output buffers.
pub fn new_call_id() -> [u8; CALL_ID_LEN] {
    let mut id = [0u8; CALL_ID_LEN];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id
}

/// A fresh 16-byte call nonce drawn straight from the OS random source, §3.2.1.
///
/// Uses `OsRng` directly (not `fresh()`); the call nonce is the per-call
/// freshness value bound into `MK_root` and the SAS.
pub fn new_call_nonce() -> [u8; CALL_NONCE_LEN] {
    // Every byte comes straight from the OS random source; the array is built
    // element by element so no constant value ever sits in the nonce buffer.
    let mut rng = rand::rngs::OsRng;
    core::array::from_fn(|_| (rng.next_u32() & 0xff) as u8)
}

/// A fresh media key share drawn from the OS random source.
pub fn new_key_share() -> Zeroizing<[u8; KEY_SHARE_LEN]> {
    let mut rng = rand::rngs::OsRng;
    Zeroizing::new(core::array::from_fn(|_| (rng.next_u32() & 0xff) as u8))
}

/// The `offer_hash` of §2.7.6: SHA-256 over the whole encoded offer body. This
/// is the value bound into the SAS; it is not stored in the body and not put on
/// the wire header.
pub fn offer_hash(encoded_offer_body: &[u8]) -> [u8; OFFER_HASH_LEN] {
    let mut h = Sha256::new();
    h.update(encoded_offer_body);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // No fixed keys, nonces or ids in tests: every id/nonce is generated at run
    // time with OsRng.

    fn sample_offer() -> Record {
        Record::Offer {
            call_id: new_call_id(),
            call_nonce: new_call_nonce(),
            key_share: new_key_share(),
            created_at_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_000_045_000,
            capabilities: vec![0x01, 0x18, 0x00],
        }
    }

    fn sample_answer() -> Record {
        Record::Answer {
            call_id: new_call_id(),
            call_nonce: new_call_nonce(),
            key_share: new_key_share(),
            created_at_ms: 1_700_000_001_000,
            capabilities: vec![0x01, 0x18],
        }
    }

    fn sample_reject() -> Record {
        Record::Reject {
            call_id: new_call_id(),
            created_at_ms: 1_700_000_002_000,
            reason: reason::DECLINED,
        }
    }

    fn sample_busy() -> Record {
        Record::Busy {
            call_id: new_call_id(),
            created_at_ms: 1_700_000_003_000,
            reason: reason::BUSY,
        }
    }

    fn sample_cancel() -> Record {
        Record::Cancel {
            call_id: new_call_id(),
            created_at_ms: 1_700_000_004_000,
            reason: reason::CANCELED,
        }
    }

    fn sample_bye() -> Record {
        Record::Bye {
            call_id: new_call_id(),
            created_at_ms: 1_700_000_005_000,
        }
    }

    fn sample_ack() -> Record {
        Record::Ack {
            call_id: new_call_id(),
            acked_kind: Kind::Offer.byte(),
        }
    }

    fn sample_collide() -> Record {
        Record::Collide {
            call_id: new_call_id(),
            peer_call_id: new_call_id(),
            created_at_ms: 1_700_000_006_000,
        }
    }

    /// Every kind round-trips: decode(encode(r)) equals r field by field.
    fn assert_round_trips(r: &Record) {
        let bytes = r.encode().expect("encode of a valid record must succeed");
        let back = Record::decode(&bytes).expect("decode of our own encode must succeed");
        assert_eq!(r.kind(), back.kind());
        assert!(r.call_id() == back.call_id());
        assert!(
            bytes == back.encode().expect("re-encode must succeed"),
            "re-encode must be byte-identical"
        );
        match (r, &back) {
            (Record::Offer { key_share: a, .. }, Record::Offer { key_share: b, .. })
            | (Record::Answer { key_share: a, .. }, Record::Answer { key_share: b, .. }) => {
                assert!(**a == **b)
            }
            _ => {}
        }
    }

    #[test]
    fn round_trip_every_kind() {
        assert_round_trips(&sample_offer());
        assert_round_trips(&sample_answer());
        assert_round_trips(&sample_reject());
        assert_round_trips(&sample_busy());
        assert_round_trips(&sample_cancel());
        assert_round_trips(&sample_bye());
        assert_round_trips(&sample_ack());
        assert_round_trips(&sample_collide());
    }

    #[test]
    fn round_trip_offer_fields() {
        let call_id = new_call_id();
        let call_nonce = new_call_nonce();
        let rec = Record::Offer {
            call_id,
            call_nonce,
            key_share: new_key_share(),
            created_at_ms: 42,
            expires_at_ms: 42 + CALL_TTL_SECONDS_DEFAULT * 1000,
            capabilities: vec![9, 8, 7, 6],
        };
        let back = Record::decode(&rec.encode().unwrap()).unwrap();
        match back {
            Record::Offer {
                call_id: id,
                call_nonce: nonce,
                key_share,
                created_at_ms,
                expires_at_ms,
                capabilities,
            } => {
                assert!(id == call_id);
                assert!(nonce == call_nonce);
                if let Record::Offer {
                    key_share: original,
                    ..
                } = &rec
                {
                    assert!(*key_share == **original);
                }
                assert_eq!(created_at_ms, 42);
                assert_eq!(expires_at_ms, 42 + 45_000);
                assert_eq!(capabilities, vec![9, 8, 7, 6]);
            }
            _ => panic!("decoded the wrong kind"),
        }
    }

    /// Truncation at every byte is rejected cleanly (never a panic).
    #[test]
    fn truncation_at_every_byte() {
        for r in [
            sample_offer(),
            sample_answer(),
            sample_reject(),
            sample_busy(),
            sample_cancel(),
            sample_bye(),
            sample_ack(),
            sample_collide(),
        ] {
            let full = r.encode().unwrap();
            for cut in 0..full.len() {
                // Any proper prefix must be an Err, not a panic, not an Ok.
                let res = Record::decode(&full[..cut]);
                if matches!(r.kind(), Kind::Offer | Kind::Answer) {
                    assert!(matches!(res, Err(SignalError::Truncated)));
                    continue;
                }
                assert!(
                    res.is_err(),
                    "prefix of length {cut} of a {:?} must not decode",
                    r.kind()
                );
            }
            // The full body decodes.
            assert!(Record::decode(&full).is_ok());
        }
    }

    /// Empty input is a clean truncation error, not a panic.
    #[test]
    fn empty_input_is_truncated() {
        assert!(matches!(Record::decode(&[]), Err(SignalError::Truncated)));
    }

    /// Trailing bytes after a complete record are rejected.
    #[test]
    fn trailing_bytes_rejected() {
        for r in [
            sample_offer(),
            sample_answer(),
            sample_reject(),
            sample_busy(),
            sample_cancel(),
            sample_bye(),
            sample_ack(),
            sample_collide(),
        ] {
            let mut bytes = r.encode().unwrap();
            bytes.push(0x00);
            assert!(
                matches!(Record::decode(&bytes), Err(SignalError::TrailingBytes)),
                "trailing byte after a {:?} must be rejected",
                r.kind()
            );
        }
    }

    /// Unknown kind bytes are rejected, including the hybrid band and bytes just
    /// outside the signal band.
    #[test]
    fn unknown_kind_rejected() {
        for bad in [0x00u8, 0x01, 0x20, 0x21, 0x22, 0x23, 0x2f, 0x38, 0xff] {
            assert!(
                Kind::from_byte(bad).is_none(),
                "{bad:#x} is not a call kind"
            );
            let body = [bad; 40];
            assert!(matches!(
                Record::decode(&body),
                Err(SignalError::UnknownKind)
            ));
        }
        for good in 0x30u8..=0x37 {
            assert!(Kind::from_byte(good).is_some(), "{good:#x} is a call kind");
            assert!(Kind::is_signal_kind(good));
        }
    }

    /// An unknown reason code is rejected (reject unknown fields) for every kind
    /// that carries a reason.
    #[test]
    fn unknown_reason_rejected() {
        for r in [sample_reject(), sample_busy(), sample_cancel()] {
            let mut bytes = r.encode().unwrap();
            // The reason byte is the last byte of a reject/busy/cancel record.
            let last = bytes.len() - 1;
            bytes[last] = 0x7f; // not a known reason code
            assert!(
                matches!(Record::decode(&bytes), Err(SignalError::UnknownReason)),
                "unknown reason after a {:?} must be rejected",
                r.kind()
            );
        }
    }

    /// An oversized length prefix is rejected before any buffer is sized.
    #[test]
    fn oversized_length_rejected() {
        // Build an offer prefix up to (and including) the capability length
        // prefix, then claim a huge length with no body following.
        let mut bytes = Vec::new();
        bytes.push(Kind::Offer.byte());
        bytes.extend_from_slice(&new_call_id());
        bytes.extend_from_slice(&new_call_nonce());
        bytes.extend_from_slice(new_key_share().as_ref());
        bytes.extend_from_slice(&1u64.to_be_bytes()); // created_at
        bytes.extend_from_slice(&2u64.to_be_bytes()); // expires_at
        bytes.extend_from_slice(&((MAX_CAPABILITIES_LEN as u16) + 1).to_be_bytes());
        assert!(matches!(
            Record::decode(&bytes),
            Err(SignalError::Oversized)
        ));
    }

    /// A length prefix at the maximum is accepted.
    #[test]
    fn capability_length_boundary() {
        let at_max = Record::Offer {
            call_id: new_call_id(),
            call_nonce: new_call_nonce(),
            key_share: new_key_share(),
            created_at_ms: 1,
            expires_at_ms: 2,
            capabilities: vec![0xAB; MAX_CAPABILITIES_LEN],
        };
        assert!(Record::decode(&at_max.encode().unwrap()).is_ok());
    }

    /// A capability block longer than the maximum fails to encode rather than
    /// truncating into the 2-byte length prefix and corrupting the frame.
    #[test]
    fn over_long_capabilities_encode_rejected() {
        for r in [
            Record::Offer {
                call_id: new_call_id(),
                call_nonce: new_call_nonce(),
                key_share: new_key_share(),
                created_at_ms: 1,
                expires_at_ms: 2,
                capabilities: vec![0xAB; MAX_CAPABILITIES_LEN + 1],
            },
            Record::Answer {
                call_id: new_call_id(),
                call_nonce: new_call_nonce(),
                key_share: new_key_share(),
                created_at_ms: 1,
                capabilities: vec![0xCD; MAX_CAPABILITIES_LEN + 1],
            },
        ] {
            assert!(matches!(r.encode(), Err(SignalError::TooLong)));
        }
    }

    /// An Ack whose acked_kind is not a defined signalling kind is rejected.
    #[test]
    fn ack_with_undefined_acked_kind_rejected() {
        for bad in [0x00u8, 0x01, 0x20, 0x2f, 0x38, 0xff] {
            assert!(
                Kind::from_byte(bad).is_none(),
                "{bad:#x} is not a call kind"
            );
            let mut bytes = sample_ack().encode().unwrap();
            // The acked_kind byte is the last byte of an ack record.
            let last = bytes.len() - 1;
            bytes[last] = bad;
            assert!(
                matches!(Record::decode(&bytes), Err(SignalError::UnknownKind)),
                "ack with acked_kind {bad:#x} must be rejected"
            );
        }
        // Every defined kind byte is an acceptable acked_kind.
        for good in 0x30u8..=0x37 {
            let mut bytes = sample_ack().encode().unwrap();
            let last = bytes.len() - 1;
            bytes[last] = good;
            assert!(
                Record::decode(&bytes).is_ok(),
                "acked_kind {good:#x} must decode"
            );
        }
    }

    /// call_id and call_nonce differ across two generated offers (OsRng, not a
    /// fixed value). The chance of a 16-byte collision is negligible.
    #[test]
    fn call_id_and_nonce_unique_across_offers() {
        let (id1, nonce1) = (new_call_id(), new_call_nonce());
        let (id2, nonce2) = (new_call_id(), new_call_nonce());
        assert!(id1 != id2, "two generated call ids must differ");
        assert!(nonce1 != nonce2, "two generated call nonces must differ");
        // call_id and call_nonce are independent draws, so they also differ.
        assert!(id1 != nonce1);
        assert!(id2 != nonce2);
    }

    #[test]
    fn key_shares_are_nonzero_and_unique() {
        let mut shares = Vec::new();
        for _ in 0..100 {
            let share = new_key_share();
            assert!(share.iter().any(|byte| *byte != 0));
            assert!(shares
                .iter()
                .all(|previous: &Zeroizing<[u8; KEY_SHARE_LEN]>| **previous != *share));
            shares.push(share);
        }
    }

    /// The offer_hash depends on the whole offer body: a one-bit change in the
    /// body changes the hash.
    #[test]
    fn offer_hash_covers_whole_body() {
        let o = sample_offer();
        let mut body = o.encode().unwrap();
        let h1 = offer_hash(&body);
        body[1] ^= 0x01; // flip a bit inside the call_id region
        let h2 = offer_hash(&body);
        assert!(h1 != h2);
        assert_eq!(h1.len(), OFFER_HASH_LEN);
    }

    /// The TTL constants keep the documented default and range.
    #[test]
    fn ttl_constants() {
        assert_eq!(CALL_TTL_SECONDS_DEFAULT, 45);
        assert_eq!(CALL_TTL_SECONDS_MIN, 30);
        assert_eq!(CALL_TTL_SECONDS_MAX, 60);
        assert!(CALL_TTL_SECONDS_MIN <= CALL_TTL_SECONDS_DEFAULT);
        assert!(CALL_TTL_SECONDS_DEFAULT <= CALL_TTL_SECONDS_MAX);
    }
}
