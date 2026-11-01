//! Wire format for the custody verbs, carried on the same channel as chat
//! (ALPN `miasma/chat/1`) but on streams of their own, each opened with a
//! one-byte stream tag so a build that does not know custody never parses one.
//! A request is one frame; its answer is one frame.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{
    holder::{CustodyError, DepositOutcome, MAX_ITEM_BYTES, MAX_LIST},
    ids::{ItemId, RecipientTag},
};
use crate::chat::crypto::Rd;

/// Written first on a bidirectional stream opened for a custody request, so the
/// server can tell it from a chat Deliver stream before reading a frame.
pub const CUSTODY_STREAM_TAG: u8 = 0xC0;

pub const REQ_DEPOSIT: u8 = 0x20;
pub const REQ_LIST: u8 = 0x21;
pub const REQ_FETCH: u8 = 0x22;
pub const REQ_DELETE: u8 = 0x23;

pub const RSP_DEPOSIT_OK: u8 = 0x30;
pub const RSP_LISTING: u8 = 0x31;
pub const RSP_ITEM: u8 = 0x32;
pub const RSP_DELETED: u8 = 0x33;
pub const RSP_REFUSED: u8 = 0x3f;

/// Largest custody frame body: a type byte, two ids, a length field and a held
/// item at its largest. Every other frame is smaller.
pub const MAX_CUSTODY_BODY: usize = 1 + 16 + 16 + 4 + MAX_ITEM_BYTES;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("i/o: {0}")]
    Io(String),
    #[error("bad frame length {0}")]
    BadLength(usize),
    #[error("unexpected frame type {0}")]
    BadType(u8),
    #[error("malformed {0}")]
    Malformed(&'static str),
}

/// A request from a depositor/collector to a holder.
#[derive(Clone, PartialEq, Eq)]
pub enum Request {
    Deposit {
        tag: RecipientTag,
        item: ItemId,
        blob: Vec<u8>,
    },
    List {
        tag: RecipientTag,
        now_ms: u64,
    },
    Fetch {
        tag: RecipientTag,
        item: ItemId,
        now_ms: u64,
    },
    Delete {
        tag: RecipientTag,
        item: ItemId,
    },
}

// The blob a deposit carries is a sealed envelope; its bytes are a secret the
// holder is trusted with but must not be spread through a log, so it does not
// derive Debug.
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deposit { .. } => f.write_str("Deposit { .. }"),
            Self::List { .. } => f.write_str("List { .. }"),
            Self::Fetch { .. } => f.write_str("Fetch { .. }"),
            Self::Delete { .. } => f.write_str("Delete { .. }"),
        }
    }
}

/// A holder's answer.
#[derive(Clone, PartialEq, Eq)]
pub enum Response {
    Deposited(DepositOutcome),
    Listing(Vec<ItemId>),
    Item(Option<Vec<u8>>),
    Deleted(bool),
    Refused(CustodyError),
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deposited(o) => write!(f, "Deposited({o:?})"),
            Self::Listing(v) => write!(f, "Listing({} items)", v.len()),
            Self::Item(o) => write!(f, "Item({})", if o.is_some() { "some" } else { "none" }),
            Self::Deleted(b) => write!(f, "Deleted({b})"),
            Self::Refused(e) => write!(f, "Refused({e:?})"),
        }
    }
}

fn error_code(e: CustodyError) -> u8 {
    match e {
        CustodyError::Disabled => 1,
        CustodyError::NotTrusted => 2,
        CustodyError::TooBig => 3,
        CustodyError::Full => 4,
        CustodyError::DepositorBudget => 5,
    }
}

fn error_from_code(c: u8) -> Option<CustodyError> {
    Some(match c {
        1 => CustodyError::Disabled,
        2 => CustodyError::NotTrusted,
        3 => CustodyError::TooBig,
        4 => CustodyError::Full,
        5 => CustodyError::DepositorBudget,
        _ => return None,
    })
}

fn frame(ty: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + payload.len());
    v.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
    v.push(ty);
    v.extend_from_slice(&payload);
    v
}

pub fn encode_request(r: &Request) -> Vec<u8> {
    match r {
        Request::Deposit { tag, item, blob } => {
            let mut p = Vec::with_capacity(16 + 16 + 4 + blob.len());
            p.extend_from_slice(&tag.0);
            p.extend_from_slice(&item.0);
            p.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            p.extend_from_slice(blob);
            frame(REQ_DEPOSIT, p)
        }
        Request::List { tag, now_ms } => {
            let mut p = Vec::with_capacity(16 + 8);
            p.extend_from_slice(&tag.0);
            p.extend_from_slice(&now_ms.to_be_bytes());
            frame(REQ_LIST, p)
        }
        Request::Fetch { tag, item, now_ms } => {
            let mut p = Vec::with_capacity(16 + 16 + 8);
            p.extend_from_slice(&tag.0);
            p.extend_from_slice(&item.0);
            p.extend_from_slice(&now_ms.to_be_bytes());
            frame(REQ_FETCH, p)
        }
        Request::Delete { tag, item } => {
            let mut p = Vec::with_capacity(16 + 16);
            p.extend_from_slice(&tag.0);
            p.extend_from_slice(&item.0);
            frame(REQ_DELETE, p)
        }
    }
}

pub fn encode_response(r: &Response) -> Vec<u8> {
    match r {
        Response::Deposited(o) => {
            let b = match o {
                DepositOutcome::Stored => 0u8,
                DepositOutcome::Duplicate => 1u8,
            };
            frame(RSP_DEPOSIT_OK, vec![b])
        }
        Response::Listing(ids) => {
            let ids = &ids[..ids.len().min(MAX_LIST)];
            let mut p = Vec::with_capacity(2 + ids.len() * 16);
            p.extend_from_slice(&(ids.len() as u16).to_be_bytes());
            for id in ids {
                p.extend_from_slice(&id.0);
            }
            frame(RSP_LISTING, p)
        }
        Response::Item(o) => {
            let mut p = Vec::new();
            match o {
                Some(b) => {
                    p.push(1);
                    p.extend_from_slice(b);
                }
                None => p.push(0),
            }
            frame(RSP_ITEM, p)
        }
        Response::Deleted(b) => frame(RSP_DELETED, vec![u8::from(*b)]),
        Response::Refused(e) => frame(RSP_REFUSED, vec![error_code(*e)]),
    }
}

fn decode_body_request(body: &[u8]) -> Result<Request, WireError> {
    let (&ty, payload) = body.split_first().ok_or(WireError::BadLength(0))?;
    let bad = |_| WireError::Malformed("request");
    let mut r = Rd::new(payload);
    match ty {
        REQ_DEPOSIT => {
            let tag = RecipientTag(r.arr::<16>().map_err(bad)?);
            let item = ItemId(r.arr::<16>().map_err(bad)?);
            let n = r.u32().map_err(bad)? as usize;
            if n > MAX_ITEM_BYTES {
                return Err(WireError::Malformed("deposit size"));
            }
            let blob = r.bytes(n).map_err(bad)?.to_vec();
            Ok(Request::Deposit { tag, item, blob })
        }
        REQ_LIST => {
            let tag = RecipientTag(r.arr::<16>().map_err(bad)?);
            let now_ms = r.u64().map_err(bad)?;
            Ok(Request::List { tag, now_ms })
        }
        REQ_FETCH => {
            let tag = RecipientTag(r.arr::<16>().map_err(bad)?);
            let item = ItemId(r.arr::<16>().map_err(bad)?);
            let now_ms = r.u64().map_err(bad)?;
            Ok(Request::Fetch { tag, item, now_ms })
        }
        REQ_DELETE => {
            let tag = RecipientTag(r.arr::<16>().map_err(bad)?);
            let item = ItemId(r.arr::<16>().map_err(bad)?);
            Ok(Request::Delete { tag, item })
        }
        other => Err(WireError::BadType(other)),
    }
}

fn decode_body_response(body: &[u8]) -> Result<Response, WireError> {
    let (&ty, payload) = body.split_first().ok_or(WireError::BadLength(0))?;
    let bad = |_| WireError::Malformed("response");
    let mut r = Rd::new(payload);
    match ty {
        RSP_DEPOSIT_OK => {
            let o = match r.u8().map_err(bad)? {
                0 => DepositOutcome::Stored,
                1 => DepositOutcome::Duplicate,
                _ => return Err(WireError::Malformed("deposit outcome")),
            };
            Ok(Response::Deposited(o))
        }
        RSP_LISTING => {
            let n = r.u16().map_err(bad)? as usize;
            if n > MAX_LIST {
                return Err(WireError::Malformed("listing count"));
            }
            let mut ids = Vec::with_capacity(n);
            for _ in 0..n {
                ids.push(ItemId(r.arr::<16>().map_err(bad)?));
            }
            Ok(Response::Listing(ids))
        }
        RSP_ITEM => match r.u8().map_err(bad)? {
            0 => Ok(Response::Item(None)),
            1 => Ok(Response::Item(Some(payload[1..].to_vec()))),
            _ => Err(WireError::Malformed("item present")),
        },
        RSP_DELETED => Ok(Response::Deleted(r.u8().map_err(bad)? != 0)),
        RSP_REFUSED => {
            let e = error_from_code(r.u8().map_err(bad)?)
                .ok_or(WireError::Malformed("refusal reason"))?;
            Ok(Response::Refused(e))
        }
        other => Err(WireError::BadType(other)),
    }
}

/// Decode one request from the front of `b`; returns it and the bytes used.
pub fn decode_request(b: &[u8]) -> Result<(Request, usize), WireError> {
    let (body, used) = split_frame(b)?;
    Ok((decode_body_request(body)?, used))
}

/// Decode one response from the front of `b`; returns it and the bytes used.
pub fn decode_response(b: &[u8]) -> Result<(Response, usize), WireError> {
    let (body, used) = split_frame(b)?;
    Ok((decode_body_response(body)?, used))
}

fn split_frame(b: &[u8]) -> Result<(&[u8], usize), WireError> {
    if b.len() < 4 {
        return Err(WireError::BadLength(b.len()));
    }
    let len = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
    if len == 0 || len > MAX_CUSTODY_BODY {
        return Err(WireError::BadLength(len));
    }
    if b.len() < 4 + len {
        return Err(WireError::BadLength(b.len()));
    }
    Ok((&b[4..4 + len], 4 + len))
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>, WireError> {
    let mut lenb = [0u8; 4];
    r.read_exact(&mut lenb)
        .await
        .map_err(|e| WireError::Io(e.to_string()))?;
    let len = u32::from_be_bytes(lenb) as usize;
    if len == 0 || len > MAX_CUSTODY_BODY {
        return Err(WireError::BadLength(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)
        .await
        .map_err(|e| WireError::Io(e.to_string()))?;
    Ok(body)
}

pub async fn write_request<W: AsyncWrite + Unpin>(w: &mut W, r: &Request) -> Result<(), WireError> {
    w.write_all(&encode_request(r))
        .await
        .map_err(|e| WireError::Io(e.to_string()))
}

pub async fn write_response<W: AsyncWrite + Unpin>(
    w: &mut W,
    r: &Response,
) -> Result<(), WireError> {
    w.write_all(&encode_response(r))
        .await
        .map_err(|e| WireError::Io(e.to_string()))
}

pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> Result<Request, WireError> {
    decode_body_request(&read_frame(r).await?)
}

pub async fn read_response<R: AsyncRead + Unpin>(r: &mut R) -> Result<Response, WireError> {
    decode_body_response(&read_frame(r).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag() -> RecipientTag {
        RecipientTag([3; 16])
    }
    fn item() -> ItemId {
        ItemId([4; 16])
    }

    #[test]
    fn requests_round_trip() {
        for r in [
            Request::Deposit {
                tag: tag(),
                item: item(),
                blob: vec![9; 300],
            },
            Request::List {
                tag: tag(),
                now_ms: 1234,
            },
            Request::Fetch {
                tag: tag(),
                item: item(),
                now_ms: 5678,
            },
            Request::Delete {
                tag: tag(),
                item: item(),
            },
        ] {
            let wire = encode_request(&r);
            assert_eq!(decode_request(&wire).unwrap(), (r.clone(), wire.len()));
            for n in 0..wire.len() {
                assert!(decode_request(&wire[..n]).is_err(), "prefix {n}");
            }
        }
    }

    #[test]
    fn responses_round_trip() {
        for r in [
            Response::Deposited(DepositOutcome::Stored),
            Response::Deposited(DepositOutcome::Duplicate),
            Response::Listing(vec![item(), ItemId([5; 16])]),
            Response::Item(Some(vec![1, 2, 3, 4])),
            Response::Item(None),
            Response::Deleted(true),
            Response::Deleted(false),
            Response::Refused(CustodyError::NotTrusted),
            Response::Refused(CustodyError::Disabled),
            Response::Refused(CustodyError::Full),
        ] {
            let wire = encode_response(&r);
            assert_eq!(decode_response(&wire).unwrap(), (r.clone(), wire.len()));
            for n in 0..wire.len() {
                assert!(decode_response(&wire[..n]).is_err(), "prefix {n}");
            }
        }
    }

    #[test]
    fn a_deposit_above_the_item_cap_is_refused_on_decode() {
        let mut p = Vec::new();
        p.extend_from_slice(&tag().0);
        p.extend_from_slice(&item().0);
        p.extend_from_slice(&((MAX_ITEM_BYTES + 1) as u32).to_be_bytes());
        let wire = frame(REQ_DEPOSIT, p);
        assert!(matches!(
            decode_request(&wire),
            Err(WireError::Malformed("deposit size"))
        ));
    }

    #[test]
    fn a_listing_above_the_cap_is_refused_on_decode() {
        let n = MAX_LIST + 1;
        let mut p = Vec::new();
        p.extend_from_slice(&(n as u16).to_be_bytes());
        p.extend_from_slice(&vec![0u8; n * 16]);
        let wire = frame(RSP_LISTING, p);
        assert!(matches!(
            decode_response(&wire),
            Err(WireError::Malformed("listing count"))
        ));
    }

    #[test]
    fn a_huge_or_zero_declared_length_is_refused_before_reading() {
        for len in [0u32, MAX_CUSTODY_BODY as u32 + 1, u32::MAX] {
            let mut wire = len.to_be_bytes().to_vec();
            wire.extend_from_slice(&[REQ_LIST, 1, 2, 3]);
            assert!(matches!(
                decode_request(&wire),
                Err(WireError::BadLength(_))
            ));
            assert!(matches!(
                decode_response(&wire),
                Err(WireError::BadLength(_))
            ));
        }
    }

    #[test]
    fn an_unknown_type_is_refused() {
        let wire = frame(0x7e, vec![0, 0]);
        assert_eq!(decode_request(&wire).unwrap_err(), WireError::BadType(0x7e));
        assert_eq!(
            decode_response(&wire).unwrap_err(),
            WireError::BadType(0x7e)
        );
    }

    #[tokio::test]
    async fn the_async_readers_round_trip_and_refuse_a_huge_length() {
        let req = Request::Fetch {
            tag: tag(),
            item: item(),
            now_ms: 9,
        };
        let buf = encode_request(&req);
        let mut r = &buf[..];
        assert_eq!(read_request(&mut r).await.unwrap(), req);

        let rsp = Response::Item(Some(vec![7; 40]));
        let buf = encode_response(&rsp);
        let mut r = &buf[..];
        assert_eq!(read_response(&mut r).await.unwrap(), rsp);

        let huge = u32::MAX.to_be_bytes();
        let mut r = &huge[..];
        assert!(matches!(
            read_request(&mut r).await,
            Err(WireError::BadLength(_))
        ));
    }

    #[test]
    fn secret_carrying_types_do_not_leak_in_debug() {
        let d = Request::Deposit {
            tag: tag(),
            item: item(),
            blob: b"sealed-envelope-bytes".to_vec(),
        };
        assert_eq!(format!("{d:?}"), "Deposit { .. }");
        let i = Response::Item(Some(b"sealed-envelope-bytes".to_vec()));
        let shown = format!("{i:?}");
        assert!(!shown.contains("sealed"), "{shown}");
        assert_eq!(shown, "Item(some)");
    }
}
