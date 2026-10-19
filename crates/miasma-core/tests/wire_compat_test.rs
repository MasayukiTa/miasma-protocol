//! Wire compatibility between releases.
//!
//! Two kinds of check, both without a network:
//!
//! * **Frozen bytes.** The messages below are written out byte for byte as the
//!   earlier releases (v0.3.2-beta.1 for the file push, v0.3.2-beta.2 for the
//!   one-to-one chat, v0.3.2-beta.3 for the catch-up frames) put them on the
//!   wire. This build must read every one of them and must still write the
//!   same bytes for the same values.
//! * **Older decoders.** `old_push` and `old_chat` are the decoders of those
//!   releases, copied from their tags into this file. Whatever this build
//!   sends to a peer of that age must be read by them.
//!
//! The last group checks the other direction in advance: what a *newer* build
//! may add (fields, enum values, record kinds) is read and set aside here
//! instead of failing the message.

use miasma_core::chat::proto::{
    self as chat, decode_frame, encode_frame, Ack, AckStatus, Frame, Message, ReadReceipt, Record,
    SyncItem,
};
use miasma_core::push::contact::{ContactCode, ContactCodeError};
use miasma_core::push::proto::{self as push, Done, Header, RejectReason, Reply};
use tokio::io::{duplex, AsyncWriteExt};

// ─── Decoders of the earlier releases (copied from their tags) ───────────────

/// `crates/miasma-core/src/push/proto.rs` at v0.3.2-beta.1 (unchanged up to
/// v0.3.2-beta.3): the structs a sender or receiver of that release decodes.
mod old_push {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    pub struct Header {
        pub v: u8,
        pub name: String,
        pub size: u64,
        pub hash: String,
        #[serde(default)]
        pub note: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum RejectReason {
        TooLarge,
        NoSpace,
        NotAllowed,
        Busy,
        BadName,
        BadRequest,
    }

    #[derive(Debug, PartialEq, Eq, Deserialize)]
    #[serde(tag = "t", rename_all = "snake_case")]
    pub enum Reply {
        Accept { offset: u64 },
        Reject { reason: RejectReason },
    }

    #[derive(Debug, Deserialize)]
    pub struct Done {
        pub ok: bool,
        #[serde(default)]
        pub saved_as: Option<String>,
        #[serde(default)]
        pub error: Option<String>,
    }

    /// `u32 big-endian length || JSON`, the length checked as in the release.
    pub fn read<T: for<'de> Deserialize<'de>>(frame: &[u8]) -> Result<T, String> {
        if frame.len() < 4 {
            return Err("short".into());
        }
        let n = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        if n == 0 || n > 16 * 1024 || frame.len() != 4 + n {
            return Err("length".into());
        }
        serde_json::from_slice(&frame[4..]).map_err(|e| e.to_string())
    }
}

/// `crates/miasma-core/src/chat/proto.rs` at v0.3.2-beta.2: the strict
/// readers of an `Ack` frame and of the text record.
mod old_chat {
    pub const MAX_TEXT_BYTES: usize = 4096;

    pub struct Rd<'a>(&'a [u8], usize);
    impl<'a> Rd<'a> {
        pub fn new(b: &'a [u8]) -> Self {
            Rd(b, 0)
        }
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            let end = self.1.checked_add(n)?;
            let s = self.0.get(self.1..end)?;
            self.1 = end;
            Some(s)
        }
        pub fn u8(&mut self) -> Option<u8> {
            self.take(1).map(|s| s[0])
        }
        pub fn u16(&mut self) -> Option<u16> {
            self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
        }
        pub fn u64(&mut self) -> Option<u64> {
            self.take(8)
                .map(|s| u64::from_be_bytes(s.try_into().unwrap()))
        }
        pub fn arr16(&mut self) -> Option<[u8; 16]> {
            self.take(16).map(|s| s.try_into().unwrap())
        }
        pub fn done(&self) -> bool {
            self.1 == self.0.len()
        }
    }

    /// Frame types the release knows: 1 = Deliver, 2 = Ack. Anything else is
    /// `BadType` and ends the connection.
    pub enum Frame {
        Deliver(Vec<u8>),
        Ack { status: u8, id: [u8; 16] },
    }

    pub fn decode_frame(b: &[u8]) -> Result<Frame, &'static str> {
        if b.len() < 5 {
            return Err("short");
        }
        let len = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if len == 0 || b.len() < 4 + len {
            return Err("length");
        }
        let (&ty, payload) = b[4..4 + len].split_first().unwrap();
        match ty {
            1 => Ok(Frame::Deliver(payload.to_vec())),
            2 => {
                let mut r = Rd::new(payload);
                let status = r.u8().ok_or("ack")?;
                let id = r.arr16().ok_or("ack")?;
                if !r.done() {
                    return Err("ack");
                }
                if status > 9 {
                    return Err("ack status");
                }
                Ok(Frame::Ack { status, id })
            }
            _ => Err("type"),
        }
    }

    pub struct Message {
        pub id: [u8; 16],
        pub seq: u64,
        pub sent_ms: u64,
        pub text: String,
    }

    /// Kind 1 only; a read receipt (kind 2) is "malformed message kind" and
    /// is answered with a bad-request acknowledgement.
    pub fn decode_message(b: &[u8]) -> Result<Message, &'static str> {
        let mut r = Rd::new(b);
        if r.u8().ok_or("m")? != 1 {
            return Err("message kind");
        }
        let id = r.arr16().ok_or("m")?;
        let seq = r.u64().ok_or("m")?;
        let sent_ms = r.u64().ok_or("m")?;
        let n = r.u16().ok_or("m")? as usize;
        if n == 0 || n > MAX_TEXT_BYTES {
            return Err("text length");
        }
        let text = std::str::from_utf8(r.take(n).ok_or("m")?)
            .map_err(|_| "text encoding")?
            .to_owned();
        if !r.done() || seq == 0 {
            return Err("message");
        }
        Ok(Message {
            id,
            seq,
            sent_ms,
            text,
        })
    }
}

// ─── Frozen bytes ────────────────────────────────────────────────────────────

fn frame(json: &str) -> Vec<u8> {
    let mut v = (json.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(json.as_bytes());
    v
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.replace(' ', "")).unwrap()
}

const HASH: &str = "abababababababababababababababababababababababababababababababab";

/// The push frames as v0.3.2-beta.1 .. beta.3 write them.
fn push_header_json() -> String {
    format!(r#"{{"v":1,"name":"report.pdf","size":5,"hash":"{HASH}","note":null}}"#)
}
const PUSH_ACCEPT: &str = r#"{"t":"accept","offset":9}"#;
const PUSH_REJECT: &str = r#"{"t":"reject","reason":"no_space"}"#;
const PUSH_DONE: &str = r#"{"ok":true,"saved_as":"x","error":null}"#;

const ID16: &str = "000102030405060708090a0b0c0d0e0f";
/// beta.2 chat: Ack(Stored) for envelope `ID16`; Deliver of `[1,2,3,4,5]`;
/// the text record; the read receipt (beta.3); the catch-up frames (beta.3).
fn chat_ack_hex(status: u8) -> String {
    format!("00000012 02 {status:02x} {ID16}")
}
const CHAT_DELIVER_HEX: &str = "00000006 01 0102030405";
const CHAT_TEXT_HEX: &str = "01 11111111111111111111111111111111 0000000000000007 \
                             0000018bcfe56800 0005 68656c6c6f";
const CHAT_RECEIPT_HEX: &str = "02 22222222222222222222222222222222 0000000000000003";
const CHAT_SYNC_HEX: &str = "0000001e 10 01 0001 33333333333333333333333333333333 \
                             0000000000000005 0003";
const CHAT_SYNC_REPLY_HEX: &str = "00000014 11 01 0001 33333333333333333333333333333333";

#[tokio::test]
async fn this_build_reads_and_writes_the_frozen_push_frames() {
    // Written by this build: the same bytes.
    let (mut a, mut b) = duplex(4096);
    push::write_frame(
        &mut a,
        &Header {
            v: 1,
            name: "report.pdf".into(),
            size: 5,
            hash: HASH.into(),
            note: None,
        },
    )
    .await
    .unwrap();
    push::write_frame(&mut a, &Reply::Accept { offset: 9 })
        .await
        .unwrap();
    push::write_frame(
        &mut a,
        &Reply::Reject {
            reason: RejectReason::NoSpace,
        },
    )
    .await
    .unwrap();
    push::write_frame(
        &mut a,
        &Done {
            ok: true,
            saved_as: Some("x".into()),
            error: None,
        },
    )
    .await
    .unwrap();
    drop(a);
    let mut got = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut b, &mut got)
        .await
        .unwrap();
    let mut want = frame(&push_header_json());
    want.extend(frame(PUSH_ACCEPT));
    want.extend(frame(PUSH_REJECT));
    want.extend(frame(PUSH_DONE));
    assert_eq!(got, want);

    // Read by this build.
    let (mut a, mut b) = duplex(4096);
    a.write_all(&want).await.unwrap();
    let h: Header = push::read_frame(&mut b).await.unwrap();
    h.validate().unwrap();
    assert_eq!((h.name.as_str(), h.size, h.note), ("report.pdf", 5, None));
    assert_eq!(
        push::read_frame::<_, Reply>(&mut b).await.unwrap(),
        Reply::Accept { offset: 9 }
    );
    assert_eq!(
        push::read_frame::<_, Reply>(&mut b).await.unwrap(),
        Reply::Reject {
            reason: RejectReason::NoSpace
        }
    );
    assert!(push::read_frame::<_, Done>(&mut b).await.unwrap().ok);
}

#[tokio::test]
async fn a_push_peer_of_an_earlier_release_reads_what_this_build_sends() {
    let (mut a, mut b) = duplex(4096);
    let mut h = Header {
        v: push::PROTOCOL_VERSION,
        name: "報告書.pdf".into(),
        size: 123,
        hash: HASH.into(),
        note: Some("note".into()),
    };
    push::write_frame(&mut a, &h).await.unwrap();
    h.note = None;
    push::write_frame(&mut a, &Reply::Accept { offset: 0 })
        .await
        .unwrap();
    for reason in [
        RejectReason::TooLarge,
        RejectReason::NoSpace,
        RejectReason::NotAllowed,
        RejectReason::Busy,
        RejectReason::BadName,
        RejectReason::BadRequest,
    ] {
        push::write_frame(&mut a, &Reply::Reject { reason })
            .await
            .unwrap();
    }
    push::write_frame(
        &mut a,
        &Done {
            ok: false,
            saved_as: None,
            error: Some("hash_mismatch".into()),
        },
    )
    .await
    .unwrap();
    drop(a);
    let mut all = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut b, &mut all)
        .await
        .unwrap();
    let mut rest = &all[..];
    let mut next = || {
        let n = 4 + u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        let (f, r) = rest.split_at(n);
        rest = r;
        f.to_vec()
    };
    let old_h: old_push::Header = old_push::read(&next()).unwrap();
    assert_eq!(
        (old_h.v, old_h.size, old_h.note.as_deref()),
        (1, 123, Some("note"))
    );
    assert_eq!(old_h.name, "報告書.pdf");
    assert_eq!(old_h.hash, HASH);
    assert_eq!(
        old_push::read::<old_push::Reply>(&next()).unwrap(),
        old_push::Reply::Accept { offset: 0 }
    );
    for want in [
        old_push::RejectReason::TooLarge,
        old_push::RejectReason::NoSpace,
        old_push::RejectReason::NotAllowed,
        old_push::RejectReason::Busy,
        old_push::RejectReason::BadName,
        old_push::RejectReason::BadRequest,
    ] {
        assert_eq!(
            old_push::read::<old_push::Reply>(&next()).unwrap(),
            old_push::Reply::Reject { reason: want }
        );
    }
    let d: old_push::Done = old_push::read(&next()).unwrap();
    assert!(!d.ok && d.saved_as.is_none() && d.error.as_deref() == Some("hash_mismatch"));
}

#[tokio::test]
async fn push_frames_from_a_newer_build_are_read_and_set_aside() {
    // A header with a newer version number and fields this build lacks.
    let newer = format!(
        r#"{{"v":2,"name":"a.txt","size":1,"hash":"{HASH}","note":null,"caps":["x"],"future":{{"a":1}}}}"#
    );
    let (mut a, mut b) = duplex(4096);
    a.write_all(&frame(&newer)).await.unwrap();
    let h: Header = push::read_frame(&mut b).await.unwrap();
    h.validate().expect("a later header version is not refused");
    // A reason and a reply kind that do not exist here.
    for (json, want) in [
        (
            r#"{"t":"reject","reason":"quota_exceeded"}"#,
            Reply::Reject {
                reason: RejectReason::Unknown,
            },
        ),
        (r#"{"t":"redirect","to":"elsewhere"}"#, Reply::Unknown),
        (
            r#"{"t":"reject","reason":"busy","retry_after_ms":5000}"#,
            Reply::Reject {
                reason: RejectReason::Busy,
            },
        ),
    ] {
        let (mut a, mut b) = duplex(4096);
        a.write_all(&frame(json)).await.unwrap();
        assert_eq!(push::read_frame::<_, Reply>(&mut b).await.unwrap(), want);
    }
    let (mut a, mut b) = duplex(4096);
    a.write_all(&frame(
        r#"{"ok":true,"saved_as":"x","error":null,"sha":"..."}"#,
    ))
    .await
    .unwrap();
    assert!(push::read_frame::<_, Done>(&mut b).await.unwrap().ok);
}

#[test]
fn this_build_reads_and_writes_the_frozen_chat_frames() {
    // Ack: every status of beta.2.
    for status in 0..=9u8 {
        let bytes = unhex(&chat_ack_hex(status));
        let (f, used) = decode_frame(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(
            f,
            Frame::Ack(Ack {
                status: AckStatus::from_code(status).unwrap(),
                envelope_id: unhex(ID16).try_into().unwrap(),
            })
        );
        assert_eq!(encode_frame(&f), bytes, "status {status}");
    }
    // Deliver.
    let bytes = unhex(CHAT_DELIVER_HEX);
    let f = Frame::Deliver(vec![1, 2, 3, 4, 5]);
    assert_eq!(decode_frame(&bytes).unwrap().0, f);
    assert_eq!(encode_frame(&f), bytes);
    // Text record (beta.2).
    let m = Message {
        id: [0x11; 16],
        seq: 7,
        sent_ms: 1_700_000_000_000,
        text: "hello".into(),
    };
    assert_eq!(Message::decode(&unhex(CHAT_TEXT_HEX)).unwrap(), m);
    assert_eq!(m.encode().unwrap(), unhex(CHAT_TEXT_HEX));
    assert_eq!(
        Record::decode(&unhex(CHAT_TEXT_HEX)).unwrap(),
        Record::Text(m)
    );
    // Read receipt (beta.3).
    let r = ReadReceipt {
        id: [0x22; 16],
        up_to_seq: 3,
    };
    assert_eq!(ReadReceipt::decode(&unhex(CHAT_RECEIPT_HEX)).unwrap(), r);
    assert_eq!(r.encode().unwrap(), unhex(CHAT_RECEIPT_HEX));
    // Catch-up frames (beta.3).
    let item = SyncItem {
        id: [0x33; 16],
        seq: 5,
        len: 3,
    };
    let sync = Frame::Sync(vec![item]);
    assert_eq!(decode_frame(&unhex(CHAT_SYNC_HEX)).unwrap().0, sync);
    assert_eq!(encode_frame(&sync), unhex(CHAT_SYNC_HEX));
    let reply = Frame::SyncReply(vec![[0x33; 16]]);
    assert_eq!(decode_frame(&unhex(CHAT_SYNC_REPLY_HEX)).unwrap().0, reply);
    assert_eq!(encode_frame(&reply), unhex(CHAT_SYNC_REPLY_HEX));
}

#[test]
fn a_chat_peer_of_beta_2_reads_what_this_build_sends() {
    for status in [
        AckStatus::Stored,
        AckStatus::Duplicate,
        AckStatus::NoSession,
        AckStatus::NotAllowed,
        AckStatus::TooBig,
        AckStatus::Rate,
        AckStatus::Busy,
        AckStatus::BadRequest,
        AckStatus::Unsupported,
        AckStatus::Failed,
    ] {
        let wire = encode_frame(&Frame::Ack(Ack {
            status,
            envelope_id: [9; 16],
        }));
        match old_chat::decode_frame(&wire).unwrap() {
            old_chat::Frame::Ack { status: s, id } => {
                assert_eq!((s, id), (status.code(), [9; 16]));
            }
            _ => panic!("not an ack"),
        }
    }
    let wire = encode_frame(&Frame::Deliver(vec![7; 300]));
    assert!(matches!(
        old_chat::decode_frame(&wire).unwrap(),
        old_chat::Frame::Deliver(p) if p == vec![7; 300]
    ));
    let m = Message {
        id: rand::random(),
        seq: 42,
        sent_ms: 1_700_000_000_123,
        text: "こんにちは、元気ですか".into(),
    };
    let old = old_chat::decode_message(&m.encode().unwrap()).unwrap();
    assert_eq!(
        (old.id, old.seq, old.sent_ms, old.text.as_str()),
        (m.id, 42, m.sent_ms, "こんにちは、元気ですか")
    );
}

/// What a build of beta.2 does with a read receipt: it answers "bad request".
/// This build therefore stops sending receipts to a contact that answers one
/// that way (see `peer_lacks_receipts` in `chat/service.rs`); this test keeps
/// the reason on record.
#[test]
fn a_beta_2_peer_does_not_understand_read_receipts() {
    let r = ReadReceipt {
        id: [1; 16],
        up_to_seq: 1,
    }
    .encode()
    .unwrap();
    assert!(old_chat::decode_message(&r).is_err());
}

#[test]
fn chat_frames_from_a_newer_build_are_read_and_set_aside() {
    // An Ack with a status this build does not know, and one with fields
    // appended after the envelope ID.
    for payload in [
        [vec![77u8], vec![5; 16]].concat(),
        [vec![0u8], vec![5; 16], vec![1, 2, 3]].concat(),
    ] {
        let mut wire = ((payload.len() + 1) as u32).to_be_bytes().to_vec();
        wire.push(2);
        wire.extend_from_slice(&payload);
        match decode_frame(&wire).unwrap().0 {
            Frame::Ack(a) => {
                assert_eq!(a.envelope_id, [5; 16]);
                assert_eq!(
                    a.status,
                    if payload[0] == 77 {
                        AckStatus::Unknown
                    } else {
                        AckStatus::Stored
                    }
                );
                assert!(!a.status.is_delivered() || payload[0] == 0);
            }
            other => panic!("{other:?}"),
        }
    }
    // A catch-up of a later version that only appended to the layout.
    let mut v2 = unhex(CHAT_SYNC_HEX);
    v2[5] = 2;
    v2.extend_from_slice(&[9, 9]);
    let n = (v2.len() - 4) as u32;
    v2[..4].copy_from_slice(&n.to_be_bytes());
    assert!(matches!(decode_frame(&v2).unwrap().0, Frame::Sync(i) if i.len() == 1));
    // Record kinds and text records with appended fields.
    assert_eq!(Record::decode(&[42, 1, 2]).unwrap(), Record::Unknown(42));
    let mut text = unhex(CHAT_TEXT_HEX);
    text.extend_from_slice(&[0xde, 0xad]);
    assert_eq!(Message::decode(&text).unwrap().text, "hello");
    let mut rec = unhex(CHAT_RECEIPT_HEX);
    rec.push(0);
    assert_eq!(ReadReceipt::decode(&rec).unwrap().up_to_seq, 3);
    // Damage is still damage.
    assert!(Record::decode(&[]).is_err());
    assert!(Message::decode(&unhex(CHAT_TEXT_HEX)[..20]).is_err());
}

#[test]
fn the_chat_constants_older_peers_rely_on_have_not_moved() {
    assert_eq!(chat::FRAME_DELIVER, 1);
    assert_eq!(chat::FRAME_ACK, 2);
    assert_eq!(chat::CLOSE_NOT_ALLOWED, 403);
    assert_eq!(chat::CLOSE_UNSUPPORTED, 426);
    assert_eq!(chat::MAX_TEXT_BYTES, 4096);
    for (status, code) in [
        (AckStatus::Stored, 0),
        (AckStatus::Duplicate, 1),
        (AckStatus::NoSession, 2),
        (AckStatus::NotAllowed, 3),
        (AckStatus::TooBig, 4),
        (AckStatus::Rate, 5),
        (AckStatus::Busy, 6),
        (AckStatus::BadRequest, 7),
        (AckStatus::Unsupported, 8),
        (AckStatus::Failed, 9),
    ] {
        assert_eq!(status.code(), code);
    }
}

// ─── Contact codes ───────────────────────────────────────────────────────────

/// The text form of v0.3.2-beta.1 .. beta.3, built here from its definition
/// (`miasma-contact:` + base58(version 1 | endpoint ID | 4 bytes of a keyed
/// BLAKE3 digest)) and not from `ContactCode` itself.
fn code_as_released(id: &[u8; 32]) -> String {
    let mut body = vec![1u8];
    body.extend_from_slice(id);
    let mut h = blake3::Hasher::new_derive_key("miasma-contact-v1 checksum");
    h.update(&body);
    body.extend_from_slice(&h.finalize().as_bytes()[..4]);
    format!("miasma-contact:{}", bs58::encode(body).into_string())
}

#[test]
fn contact_codes_of_every_release_are_accepted_and_written_the_same() {
    let id = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
        .verifying_key()
        .to_bytes();
    let text = code_as_released(&id);
    let parsed = ContactCode::parse(&text).unwrap();
    assert_eq!(parsed.endpoint_id(), &id);
    assert_eq!(ContactCode::new(id).to_string(), text);
    // Surrounding text and case of the prefix, as people paste them.
    assert!(ContactCode::parse(&format!("  {text}\n")).is_ok());
    assert!(ContactCode::parse(&format!("MIASMA-CONTACT:{}", &text[15..])).is_ok());
    // A version this build does not know says so (it does not look damaged).
    let mut body = vec![2u8];
    body.extend_from_slice(&id);
    let mut h = blake3::Hasher::new_derive_key("miasma-contact-v1 checksum");
    h.update(&body);
    body.extend_from_slice(&h.finalize().as_bytes()[..4]);
    let future = format!("miasma-contact:{}", bs58::encode(body).into_string());
    assert_eq!(
        ContactCode::parse(&future),
        Err(ContactCodeError::UnsupportedVersion(2))
    );
}
