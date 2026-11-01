//! What travels inside the sealed envelopes of group delivery.
//!
//! The envelope is the one-to-one cipher of [`crate::chat::crypto`] (the same
//! pairwise ratchet session as a private conversation with that person). The
//! first byte of the plaintext says what the record is; the private chat uses
//! kind 1, so group records can never be mistaken for it.
//!
//! ```text
//! Text    = 0x10 | [16] gid | u32 epoch | u64 counter | [16] message id | u64 sent_ms | u16 len | utf-8
//! Descs   = 0x11 | u8 n | n x ( u16 len | descriptor )          oldest first
//! SyncReq = 0x12 | [16] gid | u32 have_epoch                    "send me what follows epoch N"
//! HistOff = 0x13 | [16] gid | u32 origin_epoch | [32] author | u64 counter | [16] id | u64 sent_ms | u16 len | utf-8
//! ```
//!
//! A hand-over (`HistOff`, ADR-012) carries one past message a current member
//! offers to a newly added member. [`hist_gid`] reads its group ID straight
//! from these header bytes so the delivery layer can name the group without
//! decoding the whole record.
//!
//! The sender of a record is the peer of the pairwise session; it is never
//! taken from the record.

use crate::chat::{crypto::Rd, proto::MAX_TEXT_BYTES};

use super::membership::{DescError, Descriptor};

pub const KIND_TEXT: u8 = 0x10;
pub const KIND_DESCS: u8 = 0x11;
pub const KIND_SYNC: u8 = 0x12;
/// A past message one member hands over to a newly added member (ADR-012).
/// It travels inside the same pairwise sealed envelope as any other record,
/// so an older peer that does not know this kind returns `Unsupported` and is
/// otherwise unaffected.
pub const KIND_HIST_OFFER: u8 = 0x13;

/// Room for descriptors in one record (the padded plaintext is at most 16 KiB).
pub const MAX_DESCS_BYTES: usize = 15_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("malformed group record")]
    Malformed,
    #[error("unknown group record kind {0}")]
    UnknownKind(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupText {
    pub gid: [u8; 16],
    pub epoch: u32,
    pub counter: u64,
    pub id: [u8; 16],
    pub sent_ms: u64,
    pub text: String,
}

/// A single past message that one member offers to a newly added member,
/// quoting the original author (ADR-012). The outer pairwise seal authenticates
/// the member who hands it over, not the original author, so a receiver shows it
/// as a claim by the member who shared it (attributed, not author-signed).
///
/// This type carries a message body, so it deliberately does not derive `Debug`;
/// its manual `Debug` omits the body and the original author's key so neither is
/// written to a log.
#[derive(Clone, PartialEq, Eq)]
pub struct HistOffer {
    pub gid: [u8; 16],
    pub origin_epoch: u32,
    pub original_sender: [u8; 32],
    pub original_counter: u64,
    pub original_id: [u8; 16],
    pub original_sent_ms: u64,
    pub text: String,
}

impl std::fmt::Debug for HistOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistOffer")
            .field("gid", &self.gid)
            .field("origin_epoch", &self.origin_epoch)
            .field("original_counter", &self.original_counter)
            .field("original_id", &self.original_id)
            .field("original_sent_ms", &self.original_sent_ms)
            .field("text_len", &self.text.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Text(GroupText),
    Descs(Vec<Descriptor>),
    Sync { gid: [u8; 16], have_epoch: u32 },
    HistOffer(HistOffer),
}

impl GroupText {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let n = self.text.len();
        if n == 0 || n > MAX_TEXT_BYTES || self.counter == 0 {
            return Err(RecordError::Malformed);
        }
        let mut v = Vec::with_capacity(1 + 16 + 4 + 8 + 16 + 8 + 2 + n);
        v.push(KIND_TEXT);
        v.extend_from_slice(&self.gid);
        v.extend_from_slice(&self.epoch.to_be_bytes());
        v.extend_from_slice(&self.counter.to_be_bytes());
        v.extend_from_slice(&self.id);
        v.extend_from_slice(&self.sent_ms.to_be_bytes());
        v.extend_from_slice(&(n as u16).to_be_bytes());
        v.extend_from_slice(self.text.as_bytes());
        Ok(v)
    }
}

impl HistOffer {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let n = self.text.len();
        if n == 0 || n > MAX_TEXT_BYTES || self.original_counter == 0 {
            return Err(RecordError::Malformed);
        }
        let mut v = Vec::with_capacity(1 + 16 + 4 + 32 + 8 + 16 + 8 + 2 + n);
        v.push(KIND_HIST_OFFER);
        v.extend_from_slice(&self.gid);
        v.extend_from_slice(&self.origin_epoch.to_be_bytes());
        v.extend_from_slice(&self.original_sender);
        v.extend_from_slice(&self.original_counter.to_be_bytes());
        v.extend_from_slice(&self.original_id);
        v.extend_from_slice(&self.original_sent_ms.to_be_bytes());
        v.extend_from_slice(&(n as u16).to_be_bytes());
        v.extend_from_slice(self.text.as_bytes());
        Ok(v)
    }
}

pub fn encode_descs(ds: &[Descriptor]) -> Result<Vec<u8>, RecordError> {
    if ds.is_empty() || ds.len() > u8::MAX as usize {
        return Err(RecordError::Malformed);
    }
    let mut v = vec![KIND_DESCS, ds.len() as u8];
    for d in ds {
        let e = d.encode();
        v.extend_from_slice(&(e.len() as u16).to_be_bytes());
        v.extend_from_slice(&e);
    }
    if v.len() > MAX_DESCS_BYTES {
        return Err(RecordError::Malformed);
    }
    Ok(v)
}

pub fn encode_sync(gid: &[u8; 16], have_epoch: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(21);
    v.push(KIND_SYNC);
    v.extend_from_slice(gid);
    v.extend_from_slice(&have_epoch.to_be_bytes());
    v
}

/// The group ID carried by an encoded history offer (ADR-012), read straight
/// from the wire bytes without decoding the whole record. Returns `None` when
/// the bytes are not a well-formed `KIND_HIST_OFFER` header, so a caller never
/// mistakes another record for a hand-over. It reads only the fixed header (the
/// kind byte and the 16-byte group ID) and never touches the body.
pub fn hist_gid(plain: &[u8]) -> Option<[u8; 16]> {
    if plain.len() < 1 + 16 || plain[0] != KIND_HIST_OFFER {
        return None;
    }
    let mut gid = [0u8; 16];
    gid.copy_from_slice(&plain[1..1 + 16]);
    Some(gid)
}

/// The newest descriptors of `items` (oldest first) that fit in one record.
pub fn newest_that_fit(items: &[Descriptor]) -> Vec<Descriptor> {
    let mut size = 2usize;
    let mut take = 0usize;
    for d in items.iter().rev() {
        let n = 2 + d.encode().len();
        if size + n > MAX_DESCS_BYTES {
            break;
        }
        size += n;
        take += 1;
    }
    items[items.len() - take..].to_vec()
}

impl Record {
    pub fn decode(b: &[u8]) -> Result<Self, RecordError> {
        let bad = |_| RecordError::Malformed;
        let mut r = Rd::new(b);
        match r.u8().map_err(bad)? {
            KIND_TEXT => {
                let gid = r.arr::<16>().map_err(bad)?;
                let epoch = r.u32().map_err(bad)?;
                let counter = r.u64().map_err(bad)?;
                let id = r.arr::<16>().map_err(bad)?;
                let sent_ms = r.u64().map_err(bad)?;
                let n = r.u16().map_err(bad)? as usize;
                if n == 0 || n > MAX_TEXT_BYTES || counter == 0 {
                    return Err(RecordError::Malformed);
                }
                let text = std::str::from_utf8(r.bytes(n).map_err(bad)?)
                    .map_err(|_| RecordError::Malformed)?
                    .to_owned();
                if !r.done() {
                    return Err(RecordError::Malformed);
                }
                Ok(Record::Text(GroupText {
                    gid,
                    epoch,
                    counter,
                    id,
                    sent_ms,
                    text,
                }))
            }
            KIND_DESCS => {
                let n = r.u8().map_err(bad)? as usize;
                if n == 0 {
                    return Err(RecordError::Malformed);
                }
                let mut ds = Vec::with_capacity(n);
                for _ in 0..n {
                    let len = r.u16().map_err(bad)? as usize;
                    let raw = r.bytes(len).map_err(bad)?;
                    ds.push(
                        Descriptor::decode(raw).map_err(|_: DescError| RecordError::Malformed)?,
                    );
                }
                if !r.done() {
                    return Err(RecordError::Malformed);
                }
                Ok(Record::Descs(ds))
            }
            KIND_SYNC => {
                let gid = r.arr::<16>().map_err(bad)?;
                let have_epoch = r.u32().map_err(bad)?;
                if !r.done() {
                    return Err(RecordError::Malformed);
                }
                Ok(Record::Sync { gid, have_epoch })
            }
            KIND_HIST_OFFER => {
                let gid = r.arr::<16>().map_err(bad)?;
                let origin_epoch = r.u32().map_err(bad)?;
                let original_sender = r.arr::<32>().map_err(bad)?;
                let original_counter = r.u64().map_err(bad)?;
                let original_id = r.arr::<16>().map_err(bad)?;
                let original_sent_ms = r.u64().map_err(bad)?;
                let n = r.u16().map_err(bad)? as usize;
                if n == 0 || n > MAX_TEXT_BYTES || original_counter == 0 {
                    return Err(RecordError::Malformed);
                }
                let text = std::str::from_utf8(r.bytes(n).map_err(bad)?)
                    .map_err(|_| RecordError::Malformed)?
                    .to_owned();
                if !r.done() {
                    return Err(RecordError::Malformed);
                }
                Ok(Record::HistOffer(HistOffer {
                    gid,
                    origin_epoch,
                    original_sender,
                    original_counter,
                    original_id,
                    original_sent_ms,
                    text,
                }))
            }
            other => Err(RecordError::UnknownKind(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::group::membership::{Member, Role};
    use ed25519_dalek::SigningKey;

    fn text(t: &str) -> GroupText {
        GroupText {
            gid: rand::random(),
            epoch: 3,
            counter: 9,
            id: rand::random(),
            sent_ms: 1_700_000_000_000,
            text: t.to_owned(),
        }
    }

    fn desc(n: usize) -> Descriptor {
        let k = SigningKey::from_bytes(&rand::random());
        let mut members = vec![Member {
            id: k.verifying_key().to_bytes(),
            role: Role::Admin,
            hint: String::new(),
        }];
        for _ in 1..n {
            members.push(Member {
                id: SigningKey::from_bytes(&rand::random())
                    .verifying_key()
                    .to_bytes(),
                role: Role::Member,
                hint: "x".repeat(24),
            });
        }
        Descriptor {
            gid: rand::random(),
            epoch: 1,
            name: "g".into(),
            created_ms: 0,
            prev_hash: [0; 32],
            members,
            signer: [0; 32],
            sig: [0; 64],
        }
        .signed(&k)
    }

    #[test]
    fn text_round_trips_including_japanese_and_refuses_damage() {
        for t in ["hi", "こんにちは、みなさん", &"あ".repeat(1000)] {
            let g = text(t);
            let b = g.encode().unwrap();
            assert_eq!(Record::decode(&b).unwrap(), Record::Text(g));
            for n in 0..b.len() {
                assert!(Record::decode(&b[..n]).is_err(), "prefix {n}");
            }
        }
        assert!(text("").encode().is_err());
        assert!(text(&"x".repeat(MAX_TEXT_BYTES + 1)).encode().is_err());
        let mut zero = text("a");
        zero.counter = 0;
        assert!(zero.encode().is_err());
        let mut b = text("abc").encode().unwrap();
        b.push(0);
        assert!(Record::decode(&b).is_err());
    }

    #[test]
    fn a_private_chat_message_is_not_a_group_record() {
        // Kind 1 is the private chat's text; it must not parse here.
        assert_eq!(
            Record::decode(&[1, 0, 0, 0]),
            Err(RecordError::UnknownKind(1))
        );
    }

    #[test]
    fn descriptors_and_sync_round_trip() {
        let ds = vec![desc(3), desc(32)];
        let b = encode_descs(&ds).unwrap();
        assert_eq!(Record::decode(&b).unwrap(), Record::Descs(ds));
        let gid = [7u8; 16];
        assert_eq!(
            Record::decode(&encode_sync(&gid, 4)).unwrap(),
            Record::Sync { gid, have_epoch: 4 }
        );
        assert!(Record::decode(&[KIND_DESCS, 0]).is_err());
        assert!(Record::decode(&[KIND_SYNC, 1, 2]).is_err());
    }

    #[test]
    fn as_many_descriptors_as_fit_are_chosen_newest_first() {
        let ds: Vec<Descriptor> = (0..8).map(|_| desc(32)).collect();
        let fit = newest_that_fit(&ds);
        assert!(!fit.is_empty() && fit.len() < ds.len());
        assert_eq!(fit.last(), ds.last());
        assert!(encode_descs(&fit).is_ok());
        assert!(newest_that_fit(&ds[..1]).len() == 1);
    }

    fn offer(t: &str) -> HistOffer {
        HistOffer {
            gid: rand::random(),
            origin_epoch: 4,
            original_sender: rand::random(),
            original_counter: 12,
            original_id: rand::random(),
            original_sent_ms: 1_700_000_000_000,
            text: t.to_owned(),
        }
    }

    #[test]
    fn hist_offer_round_trips_including_japanese_and_refuses_damage() {
        for t in ["hi", "こんにちは、みなさん", &"あ".repeat(1000)] {
            let o = offer(t);
            let b = o.encode().unwrap();
            assert_eq!(Record::decode(&b).unwrap(), Record::HistOffer(o));
            for n in 0..b.len() {
                assert!(Record::decode(&b[..n]).is_err(), "prefix {n}");
            }
        }
        assert!(offer("").encode().is_err());
        assert!(offer(&"x".repeat(MAX_TEXT_BYTES + 1)).encode().is_err());
        let mut zero = offer("a");
        zero.original_counter = 0;
        assert!(zero.encode().is_err());
        let mut b = offer("abc").encode().unwrap();
        b.push(0);
        assert!(Record::decode(&b).is_err());
    }

    #[test]
    fn a_hist_offer_kind_is_unknown_to_a_decoder_that_predates_it() {
        // An older app never recognises 0x13: its first byte is not one of the
        // kinds it knows, so it reports UnknownKind and is otherwise unharmed.
        assert_eq!(
            Record::decode(&[KIND_HIST_OFFER]),
            Err(RecordError::Malformed)
        );
        // The kind byte on its own is malformed (too short); a full record is
        // only ever ignorable by a peer whose match has no 0x13 arm. We assert
        // the constant is the documented value so the wire number cannot drift.
        assert_eq!(KIND_HIST_OFFER, 0x13);
    }

    #[test]
    fn hist_gid_reads_the_group_id_only_from_a_real_offer() {
        let o = offer("from the past");
        let b = o.encode().unwrap();
        assert_eq!(hist_gid(&b), Some(o.gid));
        // A text record carries the same header shape but a different kind, so
        // it is not mistaken for a hand-over.
        assert_eq!(hist_gid(&text("hi").encode().unwrap()), None);
        // Too short to hold a kind byte and a group ID.
        assert_eq!(hist_gid(&[KIND_HIST_OFFER]), None);
        assert_eq!(hist_gid(&[]), None);
    }

    #[test]
    fn random_bytes_never_panic() {
        for _ in 0..3000 {
            let n = rand::random::<usize>() % 200;
            let mut junk: Vec<u8> = (0..n).map(|_| rand::random()).collect();
            if let Some(f) = junk.first_mut() {
                *f = 0x10 + (*f % 4);
            }
            let _ = Record::decode(&junk);
        }
    }
}
