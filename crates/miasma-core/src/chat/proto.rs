//! Wire format of `miasma/chat/1`.
//!
//! One message = one bidirectional stream. The sender writes one frame
//! (`Deliver`) and the receiver answers with one frame (`Ack`).
//!
//! ```text
//! frame   = u32 body_len (big endian) | u8 type | payload      body_len = 1 + payload
//! Deliver = type 0x01, payload = a sealed envelope (see crypto.rs)
//! Ack     = type 0x02, payload = u8 status | [16] envelope id
//! ```
//!
//! The declared length is checked against [`MAX_FRAME_BODY`] before any buffer
//! is sized, a frame that ends early is an error, and nothing after the
//! declared length is read.
//!
//! Inside the sealed envelope sits the message record:
//!
//! ```text
//! u8 kind (1 = text) | [16] message id | u64 seq | u64 sent_ms | u16 len | utf-8 text
//! u8 kind (2 = read receipt) | [16] receipt id | u64 up_to_seq
//! ```
//!
//! `seq` counts the sender's messages to this contact (1, 2, ...); the receiver
//! applies each `seq` once. A read receipt is padded into the same buckets as
//! a text, so on the wire it is the size of a short message.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::crypto::{Rd, MAX_CIPHERTEXT, MAX_HEADER_BYTES};

/// Largest message text in this version, in bytes.
pub const MAX_TEXT_BYTES: usize = 4096;
/// Largest frame body: type byte, envelope header, length field, ciphertext.
pub const MAX_FRAME_BODY: usize = 1 + MAX_HEADER_BYTES + 4 + MAX_CIPHERTEXT;

pub const FRAME_DELIVER: u8 = 0x01;
pub const FRAME_ACK: u8 = 0x02;

/// QUIC application close codes (the same numbers as the file push).
pub const CLOSE_OK: u32 = 0;
pub const CLOSE_BAD_REQUEST: u32 = 400;
pub const CLOSE_NOT_ALLOWED: u32 = 403;
/// The peer speaks a newer protocol than we do.
pub const CLOSE_UNSUPPORTED: u32 = 426;
pub const CLOSE_RATE: u32 = 429;

const KIND_TEXT: u8 = 1;
const KIND_READ: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtoError {
    #[error("i/o: {0}")]
    Io(String),
    #[error("bad frame length {0}")]
    BadLength(usize),
    #[error("unexpected frame type {0}")]
    BadType(u8),
    #[error("malformed {0}")]
    Malformed(&'static str),
}

/// Why the receiver did or did not keep a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckStatus {
    /// Applied and written down.
    Stored,
    /// Already applied earlier; nothing changed.
    Duplicate,
    /// The receiver has no session this message belongs to; start a new one.
    NoSession,
    /// The sender is not a contact the receiver accepts messages from.
    NotAllowed,
    TooBig,
    /// Too many messages too fast; try later.
    Rate,
    Busy,
    /// The message did not authenticate, was replayed or malformed.
    BadRequest,
    /// Newer protocol or an option this version does not know.
    Unsupported,
    /// The receiver could not store it (disk, key); try later.
    Failed,
}

impl AckStatus {
    pub fn code(self) -> u8 {
        match self {
            Self::Stored => 0,
            Self::Duplicate => 1,
            Self::NoSession => 2,
            Self::NotAllowed => 3,
            Self::TooBig => 4,
            Self::Rate => 5,
            Self::Busy => 6,
            Self::BadRequest => 7,
            Self::Unsupported => 8,
            Self::Failed => 9,
        }
    }

    pub fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => Self::Stored,
            1 => Self::Duplicate,
            2 => Self::NoSession,
            3 => Self::NotAllowed,
            4 => Self::TooBig,
            5 => Self::Rate,
            6 => Self::Busy,
            7 => Self::BadRequest,
            8 => Self::Unsupported,
            9 => Self::Failed,
            _ => return None,
        })
    }

    /// The receiver has the message (now or before).
    pub fn is_delivered(self) -> bool {
        matches!(self, Self::Stored | Self::Duplicate)
    }
}

/// Reasons a message ends up `failed`. Stable strings for the IPC.
pub mod fail {
    pub const NOT_ALLOWED: &str = "not_allowed";
    pub const TOO_BIG: &str = "too_big";
    pub const REJECTED: &str = "rejected";
    pub const UNSUPPORTED: &str = "unsupported";
    pub const CONTACT_REMOVED: &str = "contact_removed";
    pub const SEND_DISABLED: &str = "send_disabled";
    pub const EXPIRED: &str = "expired";
    pub const SESSION: &str = "session";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    pub status: AckStatus,
    pub envelope_id: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Deliver(Vec<u8>),
    Ack(Ack),
}

/// The bytes of a frame (length prefix included).
pub fn encode_frame(f: &Frame) -> Vec<u8> {
    let (ty, payload): (u8, Vec<u8>) = match f {
        Frame::Deliver(env) => (FRAME_DELIVER, env.clone()),
        Frame::Ack(a) => {
            let mut p = Vec::with_capacity(17);
            p.push(a.status.code());
            p.extend_from_slice(&a.envelope_id);
            (FRAME_ACK, p)
        }
    };
    let mut v = Vec::with_capacity(5 + payload.len());
    v.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
    v.push(ty);
    v.extend_from_slice(&payload);
    v
}

/// Parse the body of a frame (type byte and payload).
pub fn decode_body(body: &[u8]) -> Result<Frame, ProtoError> {
    let (&ty, payload) = body.split_first().ok_or(ProtoError::BadLength(0))?;
    match ty {
        FRAME_DELIVER => Ok(Frame::Deliver(payload.to_vec())),
        FRAME_ACK => {
            let mut r = Rd::new(payload);
            let status = r.u8().map_err(|_| ProtoError::Malformed("ack"))?;
            let id = r.arr::<16>().map_err(|_| ProtoError::Malformed("ack"))?;
            if !r.done() {
                return Err(ProtoError::Malformed("ack"));
            }
            let status = AckStatus::from_code(status).ok_or(ProtoError::Malformed("ack status"))?;
            Ok(Frame::Ack(Ack {
                status,
                envelope_id: id,
            }))
        }
        other => Err(ProtoError::BadType(other)),
    }
}

/// Decode one frame from the front of `b`; returns it and the bytes used.
/// Used by the tests and by anything that already holds the bytes.
pub fn decode_frame(b: &[u8]) -> Result<(Frame, usize), ProtoError> {
    if b.len() < 4 {
        return Err(ProtoError::BadLength(b.len()));
    }
    let len = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    if len == 0 || len > MAX_FRAME_BODY {
        return Err(ProtoError::BadLength(len));
    }
    if b.len() < 4 + len {
        return Err(ProtoError::BadLength(b.len()));
    }
    Ok((decode_body(&b[4..4 + len])?, 4 + len))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, f: &Frame) -> Result<(), ProtoError> {
    w.write_all(&encode_frame(f))
        .await
        .map_err(|e| ProtoError::Io(e.to_string()))
}

/// Read one frame. The buffer is sized only after the declared length passed
/// the check, and only as much is read as was declared.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Frame, ProtoError> {
    let mut lenb = [0u8; 4];
    r.read_exact(&mut lenb)
        .await
        .map_err(|e| ProtoError::Io(e.to_string()))?;
    let len = u32::from_be_bytes(lenb) as usize;
    if len == 0 || len > MAX_FRAME_BODY {
        return Err(ProtoError::BadLength(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)
        .await
        .map_err(|e| ProtoError::Io(e.to_string()))?;
    decode_body(&body)
}

// ─── Message record ──────────────────────────────────────────────────────────

/// One chat message as the two sides agree on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: [u8; 16],
    /// The sender's counter for this contact; starts at 1.
    pub seq: u64,
    pub sent_ms: u64,
    pub text: String,
}

impl Message {
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let n = self.text.len();
        if n == 0 || n > MAX_TEXT_BYTES {
            return Err(ProtoError::Malformed("text length"));
        }
        let mut v = Vec::with_capacity(1 + 16 + 8 + 8 + 2 + n);
        v.push(KIND_TEXT);
        v.extend_from_slice(&self.id);
        v.extend_from_slice(&self.seq.to_be_bytes());
        v.extend_from_slice(&self.sent_ms.to_be_bytes());
        v.extend_from_slice(&(n as u16).to_be_bytes());
        v.extend_from_slice(self.text.as_bytes());
        Ok(v)
    }

    pub fn decode(b: &[u8]) -> Result<Self, ProtoError> {
        let bad = |_| ProtoError::Malformed("message");
        let mut r = Rd::new(b);
        if r.u8().map_err(bad)? != KIND_TEXT {
            return Err(ProtoError::Malformed("message kind"));
        }
        let id = r.arr::<16>().map_err(bad)?;
        let seq = r.u64().map_err(bad)?;
        let sent_ms = r.u64().map_err(bad)?;
        let n = r.u16().map_err(bad)? as usize;
        if n == 0 || n > MAX_TEXT_BYTES {
            return Err(ProtoError::Malformed("text length"));
        }
        let text = std::str::from_utf8(r.bytes(n).map_err(bad)?)
            .map_err(|_| ProtoError::Malformed("text encoding"))?
            .to_owned();
        if !r.done() || seq == 0 {
            return Err(ProtoError::Malformed("message"));
        }
        Ok(Self {
            id,
            seq,
            sent_ms,
            text,
        })
    }
}

// ─── Read receipt record ─────────────────────────────────────────────────────

/// "I have read your messages up to number `up_to_seq`." It travels in the same
/// sealed, padded envelope as a text and carries no text of its own.
///
/// ```text
/// u8 kind (2 = read receipt) | [16] receipt id | u64 up_to_seq
/// ```
///
/// A receipt has no sequence number of its own and is never answered by
/// another receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadReceipt {
    pub id: [u8; 16],
    pub up_to_seq: u64,
}

impl ReadReceipt {
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        if self.up_to_seq == 0 {
            return Err(ProtoError::Malformed("receipt"));
        }
        let mut v = Vec::with_capacity(1 + 16 + 8);
        v.push(KIND_READ);
        v.extend_from_slice(&self.id);
        v.extend_from_slice(&self.up_to_seq.to_be_bytes());
        Ok(v)
    }

    pub fn decode(b: &[u8]) -> Result<Self, ProtoError> {
        let bad = |_| ProtoError::Malformed("receipt");
        let mut r = Rd::new(b);
        if r.u8().map_err(bad)? != KIND_READ {
            return Err(ProtoError::Malformed("receipt kind"));
        }
        let id = r.arr::<16>().map_err(bad)?;
        let up_to_seq = r.u64().map_err(bad)?;
        if !r.done() || up_to_seq == 0 {
            return Err(ProtoError::Malformed("receipt"));
        }
        Ok(Self { id, up_to_seq })
    }
}

/// What a decrypted envelope holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Text(Message),
    Read(ReadReceipt),
}

impl Record {
    pub fn decode(b: &[u8]) -> Result<Self, ProtoError> {
        match b.first() {
            Some(&KIND_TEXT) => Message::decode(b).map(Record::Text),
            Some(&KIND_READ) => ReadReceipt::decode(b).map(Record::Read),
            _ => Err(ProtoError::Malformed("record kind")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipts_round_trip_and_reject_damage() {
        let r = ReadReceipt {
            id: rand::random(),
            up_to_seq: 42,
        };
        let bytes = r.encode().unwrap();
        assert_eq!(ReadReceipt::decode(&bytes).unwrap(), r);
        assert_eq!(Record::decode(&bytes).unwrap(), Record::Read(r));
        for n in 0..bytes.len() {
            assert!(ReadReceipt::decode(&bytes[..n]).is_err(), "prefix {n}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(ReadReceipt::decode(&longer).is_err());
        assert!(ReadReceipt {
            id: [0; 16],
            up_to_seq: 0
        }
        .encode()
        .is_err());
        let mut zero = bytes.clone();
        zero[17..].fill(0);
        assert!(ReadReceipt::decode(&zero).is_err());
        // A text is not a receipt and the other way round.
        let t = msg("hi").encode().unwrap();
        assert!(ReadReceipt::decode(&t).is_err());
        assert!(Message::decode(&bytes).is_err());
        assert!(Record::decode(&[]).is_err());
        assert!(Record::decode(&[9, 0, 0]).is_err());
    }

    fn msg(text: &str) -> Message {
        Message {
            id: rand::random(),
            seq: 7,
            sent_ms: 1_700_000_000_000,
            text: text.to_owned(),
        }
    }

    #[test]
    fn frames_round_trip() {
        let d = Frame::Deliver(vec![1, 2, 3, 4, 5]);
        let (back, used) = decode_frame(&encode_frame(&d)).unwrap();
        assert_eq!(back, d);
        assert_eq!(used, encode_frame(&d).len());
        for status in 0..=9u8 {
            let a = Frame::Ack(Ack {
                status: AckStatus::from_code(status).unwrap(),
                envelope_id: rand::random(),
            });
            assert_eq!(decode_frame(&encode_frame(&a)).unwrap().0, a);
        }
    }

    #[test]
    fn every_truncation_of_a_frame_is_an_error() {
        for f in [
            Frame::Deliver(vec![9; 40]),
            Frame::Ack(Ack {
                status: AckStatus::Stored,
                envelope_id: rand::random(),
            }),
        ] {
            let wire = encode_frame(&f);
            for n in 0..wire.len() {
                assert!(decode_frame(&wire[..n]).is_err(), "prefix {n}");
            }
        }
    }

    #[test]
    fn a_huge_or_zero_declared_length_is_refused_before_reading() {
        for len in [0u32, MAX_FRAME_BODY as u32 + 1, u32::MAX] {
            let mut wire = len.to_be_bytes().to_vec();
            wire.extend_from_slice(&[FRAME_DELIVER, 1, 2, 3]);
            assert!(matches!(decode_frame(&wire), Err(ProtoError::BadLength(_))));
        }
    }

    #[tokio::test]
    async fn the_async_reader_refuses_a_huge_length_without_allocating_it() {
        let wire = u32::MAX.to_be_bytes();
        let mut r = &wire[..];
        assert!(matches!(
            read_frame(&mut r).await,
            Err(ProtoError::BadLength(_))
        ));
        // A stream that ends inside the body is an error, not a hang or panic.
        let mut cut = Vec::new();
        cut.extend_from_slice(&100u32.to_be_bytes());
        cut.extend_from_slice(&[FRAME_DELIVER; 10]);
        let mut r = &cut[..];
        assert!(matches!(read_frame(&mut r).await, Err(ProtoError::Io(_))));
        let full = encode_frame(&Frame::Deliver(vec![5; 20]));
        let mut r = &full[..];
        assert_eq!(
            read_frame(&mut r).await.unwrap(),
            Frame::Deliver(vec![5; 20])
        );
    }

    #[test]
    fn unknown_types_and_bad_acks_are_refused() {
        let mut wire = 2u32.to_be_bytes().to_vec();
        wire.extend_from_slice(&[0x7f, 0]);
        assert_eq!(decode_frame(&wire), Err(ProtoError::BadType(0x7f)));
        // Ack with an unknown status, short, or long.
        for payload in [
            vec![200u8; 17],
            vec![0u8; 5],
            vec![0u8; 18],
            Vec::<u8>::new(),
        ] {
            let mut wire = ((payload.len() + 1) as u32).to_be_bytes().to_vec();
            wire.push(FRAME_ACK);
            wire.extend_from_slice(&payload);
            assert!(decode_frame(&wire).is_err());
        }
    }

    #[test]
    fn random_bytes_never_panic_the_decoders() {
        for _ in 0..2000 {
            let n = rand::random::<usize>() % 80;
            let junk: Vec<u8> = (0..n).map(|_| rand::random()).collect();
            let _ = decode_frame(&junk);
            let _ = decode_body(&junk);
            let _ = Message::decode(&junk);
            let _ = super::super::crypto::Envelope::decode(&junk);
        }
    }

    #[test]
    fn messages_round_trip_including_japanese() {
        for t in ["hello", "こんにちは、元気ですか", &"あ".repeat(1000)] {
            let m = msg(t);
            assert_eq!(Message::decode(&m.encode().unwrap()).unwrap(), m);
        }
    }

    #[test]
    fn message_limits_are_enforced_on_both_sides() {
        assert!(msg("").encode().is_err());
        assert!(msg(&"x".repeat(MAX_TEXT_BYTES)).encode().is_ok());
        assert!(msg(&"x".repeat(MAX_TEXT_BYTES + 1)).encode().is_err());
        let good = msg("abc").encode().unwrap();
        for n in 0..good.len() {
            assert!(Message::decode(&good[..n]).is_err(), "prefix {n}");
        }
        let mut longer = good.clone();
        longer.push(0);
        assert!(Message::decode(&longer).is_err());
        let mut bad_kind = good.clone();
        bad_kind[0] = 9;
        assert!(Message::decode(&bad_kind).is_err());
        let mut bad_utf8 = good.clone();
        let last = bad_utf8.len() - 1;
        bad_utf8[last] = 0xff;
        assert!(Message::decode(&bad_utf8).is_err());
        // A declared text length above the cap, with the bytes present.
        let mut big = good[..1 + 16 + 8 + 8].to_vec();
        big.extend_from_slice(&((MAX_TEXT_BYTES + 1) as u16).to_be_bytes());
        big.extend_from_slice(&vec![b'x'; MAX_TEXT_BYTES + 1]);
        assert!(Message::decode(&big).is_err());
        // seq 0 is not valid.
        let mut zero = msg("abc");
        zero.seq = 0;
        assert!(Message::decode(&zero.encode().unwrap()).is_err());
    }
}
