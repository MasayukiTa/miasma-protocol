//! Wire messages of `miasma/push/1`.
//!
//! One transfer is one bidirectional stream:
//!
//! ```text
//! sender   -> Header                (frame)
//! receiver -> Reply::Accept{offset} | Reply::Reject{reason}   (frame)
//! sender   -> raw file bytes [offset..size], then finishes its send side
//! receiver -> Done{ok, saved_as, error}                        (frame)
//! ```
//!
//! A frame is `u32 big-endian length || JSON`. The declared length is checked
//! against [`MAX_FRAME_BYTES`] before any buffer is sized from it. Nothing in
//! a message is trusted for identity: who the sender is comes from the QUIC/TLS
//! handshake only.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// ALPN of the push protocol (the same constant lives in `iroh_direct`).
pub const PROTOCOL_VERSION: u8 = 1;
/// A header or reply is tiny; anything bigger is hostile or broken.
pub const MAX_FRAME_BYTES: usize = 16 * 1024;
/// Longest note accepted (characters).
pub const MAX_NOTE_CHARS: usize = 500;
/// Longest raw name accepted before sanitising (bytes).
pub const MAX_RAW_NAME_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub v: u8,
    /// Base name as the sender knows it. The receiver sanitises it again.
    pub name: String,
    pub size: u64,
    /// BLAKE3 of the whole file, lower-case hex (64 chars).
    pub hash: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    TooLarge,
    NoSpace,
    NotAllowed,
    Busy,
    BadName,
    /// Malformed header or unsupported protocol version.
    BadRequest,
    /// A reason a newer build added; this build only knows that it was refused.
    #[serde(other)]
    Unknown,
}

impl RejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::NoSpace => "no_space",
            Self::NotAllowed => "not_allowed",
            Self::Busy => "busy",
            Self::BadName => "bad_name",
            Self::BadRequest => "bad_request",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Reply {
    Accept {
        offset: u64,
    },
    Reject {
        reason: RejectReason,
    },
    /// A reply kind a newer build added; the sender stops with a clear text.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Done {
    pub ok: bool,
    /// File name it was saved under (display only).
    #[serde(default)]
    pub saved_as: Option<String>,
    /// Short machine-ish reason when `ok` is false (`hash_mismatch`, ...).
    #[serde(default)]
    pub error: Option<String>,
}

/// QUIC application error codes used on `Connection::close`.
pub const CLOSE_OK: u32 = 0;
/// The dialer is not a registered contact (or may not push).
pub const CLOSE_NOT_ALLOWED: u32 = 403;
pub const CLOSE_BAD_REQUEST: u32 = 400;
pub const CLOSE_CANCELLED: u32 = 499;

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("i/o: {0}")]
    Io(String),
    #[error("frame length {0} is out of bounds")]
    BadLength(usize),
    #[error("malformed message: {0}")]
    Malformed(String),
    #[error("unsupported protocol version {0}")]
    Version(u8),
    #[error("invalid header: {0}")]
    Invalid(&'static str),
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    msg: &T,
) -> Result<(), ProtoError> {
    let body = serde_json::to_vec(msg).map_err(|e| ProtoError::Malformed(e.to_string()))?;
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(ProtoError::BadLength(body.len()));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())
        .await
        .map_err(|e| ProtoError::Io(e.to_string()))?;
    w.write_all(&body)
        .await
        .map_err(|e| ProtoError::Io(e.to_string()))?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(
    r: &mut R,
) -> Result<T, ProtoError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)
        .await
        .map_err(|e| ProtoError::Io(e.to_string()))?;
    let declared = u32::from_be_bytes(len) as usize;
    if declared == 0 || declared > MAX_FRAME_BYTES {
        return Err(ProtoError::BadLength(declared));
    }
    // Grows with what arrives: a peer that declares much and sends nothing
    // costs nothing beyond its timeout.
    let mut body = Vec::with_capacity(declared.min(4096));
    (&mut *r)
        .take(declared as u64)
        .read_to_end(&mut body)
        .await
        .map_err(|e| ProtoError::Io(e.to_string()))?;
    if body.len() != declared {
        return Err(ProtoError::Io("message cut short".into()));
    }
    serde_json::from_slice(&body).map_err(|e| ProtoError::Malformed(e.to_string()))
}

impl Header {
    /// Structural checks that need no policy: version, hash shape, lengths.
    pub fn validate(&self) -> Result<(), ProtoError> {
        // Later versions only add optional fields to this header, so any
        // version from 1 up is read; 0 was never sent.
        if self.v < PROTOCOL_VERSION {
            return Err(ProtoError::Version(self.v));
        }
        if self.hash.len() != 64 || !self.hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ProtoError::Invalid("hash"));
        }
        if self.name.is_empty() || self.name.len() > MAX_RAW_NAME_BYTES {
            return Err(ProtoError::Invalid("name"));
        }
        if let Some(n) = &self.note {
            if n.chars().count() > MAX_NOTE_CHARS {
                return Err(ProtoError::Invalid("note"));
            }
        }
        Ok(())
    }

    /// The hash as bytes (after [`validate`](Self::validate)).
    pub fn hash_bytes(&self) -> Option<[u8; 32]> {
        hex::decode(&self.hash).ok()?.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn header() -> Header {
        Header {
            v: PROTOCOL_VERSION,
            name: "報告書.pdf".into(),
            size: 5,
            hash: "ab".repeat(32),
            note: None,
        }
    }

    #[tokio::test]
    async fn header_round_trip() {
        let (mut a, mut b) = duplex(1024);
        write_frame(&mut a, &header()).await.unwrap();
        let h: Header = read_frame(&mut b).await.unwrap();
        assert_eq!(h, header());
        h.validate().unwrap();
        assert_eq!(h.hash_bytes().unwrap(), [0xab; 32]);
    }

    #[tokio::test]
    async fn reply_and_done_round_trip() {
        let (mut a, mut b) = duplex(1024);
        write_frame(
            &mut a,
            &Reply::Reject {
                reason: RejectReason::NoSpace,
            },
        )
        .await
        .unwrap();
        write_frame(&mut a, &Reply::Accept { offset: 9 })
            .await
            .unwrap();
        write_frame(
            &mut a,
            &Done {
                ok: true,
                saved_as: Some("x".into()),
                error: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            read_frame::<_, Reply>(&mut b).await.unwrap(),
            Reply::Reject {
                reason: RejectReason::NoSpace
            }
        );
        assert_eq!(
            read_frame::<_, Reply>(&mut b).await.unwrap(),
            Reply::Accept { offset: 9 }
        );
        assert!(read_frame::<_, Done>(&mut b).await.unwrap().ok);
    }

    #[tokio::test]
    async fn huge_declared_length_is_refused_without_allocating() {
        let (mut a, mut b) = duplex(64);
        a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        assert!(matches!(
            read_frame::<_, Header>(&mut b).await,
            Err(ProtoError::BadLength(_))
        ));
        let (mut a, mut b) = duplex(64);
        a.write_all(&0u32.to_be_bytes()).await.unwrap();
        assert!(matches!(
            read_frame::<_, Header>(&mut b).await,
            Err(ProtoError::BadLength(0))
        ));
    }

    #[tokio::test]
    async fn truncated_and_garbage_frames_error_cleanly() {
        // Truncated body.
        let (mut a, mut b) = duplex(64);
        a.write_all(&100u32.to_be_bytes()).await.unwrap();
        a.write_all(b"{\"v\":1").await.unwrap();
        drop(a);
        assert!(read_frame::<_, Header>(&mut b).await.is_err());
        // Truncated length.
        let (mut a, mut b) = duplex(64);
        a.write_all(&[0, 0]).await.unwrap();
        drop(a);
        assert!(read_frame::<_, Header>(&mut b).await.is_err());
        // Not JSON.
        let (mut a, mut b) = duplex(64);
        a.write_all(&4u32.to_be_bytes()).await.unwrap();
        a.write_all(b"\xff\xfe\x00\x01").await.unwrap();
        assert!(matches!(
            read_frame::<_, Header>(&mut b).await,
            Err(ProtoError::Malformed(_))
        ));
    }

    #[test]
    fn validation() {
        let mut h = header();
        h.v = 0;
        assert!(matches!(h.validate(), Err(ProtoError::Version(0))));
        let mut h = header();
        h.hash = "zz".repeat(32);
        assert!(h.validate().is_err());
        let mut h = header();
        h.hash = "ab".repeat(31);
        assert!(h.validate().is_err());
        let mut h = header();
        h.name = String::new();
        assert!(h.validate().is_err());
        let mut h = header();
        h.name = "a".repeat(MAX_RAW_NAME_BYTES + 1);
        assert!(h.validate().is_err());
        let mut h = header();
        h.note = Some("x".repeat(MAX_NOTE_CHARS + 1));
        assert!(h.validate().is_err());
    }
}
