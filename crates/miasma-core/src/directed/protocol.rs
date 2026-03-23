//! Directed sharing protocol — `/miasma/directed/1.0.0`.
//!
//! Request-response protocol for the directed sharing handshake:
//! 1. Sender sends `Invite` with envelope → Recipient returns challenge
//! 2. Sender sends `Confirm` with challenge code → Recipient confirms or rejects
//! 3. Either side sends `Revoke` → Acknowledged
//! 4. Recipient sends `StatusQuery` → Returns current envelope state

use serde::{Deserialize, Serialize};

use super::envelope::{DirectedEnvelope, EnvelopeState};

/// Max message size for directed protocol (32 KiB).
pub const DIRECTED_MSG_MAX: usize = 32 * 1024;

// ─── Wire types ──────────────────────────────────────────────────────────────

/// Request sent over `/miasma/directed/1.0.0`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DirectedRequest {
    /// Sender invites recipient to receive a directed share.
    Invite {
        envelope: DirectedEnvelope,
    },
    /// Sender submits the confirmation challenge code.
    Confirm {
        envelope_id: [u8; 32],
        challenge_code: String,
    },
    /// Sender revokes a previously sent directed share.
    SenderRevoke {
        envelope_id: [u8; 32],
    },
    /// Query the current state of an envelope.
    StatusQuery {
        envelope_id: [u8; 32],
    },
}

/// Response to a `DirectedRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DirectedResponse {
    /// Invite accepted — recipient generated a challenge.
    /// The challenge code is shown on the recipient's screen (not in this message).
    InviteAccepted {
        envelope_id: [u8; 32],
    },
    /// Challenge confirmed correctly — content is now retrievable.
    Confirmed {
        envelope_id: [u8; 32],
    },
    /// Challenge verification failed.
    ChallengeFailed {
        envelope_id: [u8; 32],
        attempts_remaining: u8,
    },
    /// Revocation acknowledged.
    Revoked {
        envelope_id: [u8; 32],
    },
    /// Current envelope state.
    Status {
        envelope_id: [u8; 32],
        state: EnvelopeState,
    },
    /// Error response.
    Error(String),
}

// ─── Codec ──────────────────────────────────────────────────────────────────

/// Bincode + 4-byte LE length-prefix codec for `/miasma/directed/1.0.0`.
#[derive(Clone, Default)]
pub struct DirectedCodec;

#[async_trait::async_trait]
impl libp2p::request_response::Codec for DirectedCodec {
    type Protocol = libp2p::StreamProtocol;
    type Request = DirectedRequest;
    type Response = DirectedResponse;

    async fn read_request<T>(
        &mut self,
        _: &libp2p::StreamProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > DIRECTED_MSG_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "directed msg too large",
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _: &libp2p::StreamProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > DIRECTED_MSG_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "directed response too large",
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &libp2p::StreamProtocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        use futures::AsyncWriteExt;
        let buf = bincode::serialize(&req)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        io.write_all(&(buf.len() as u32).to_le_bytes()).await?;
        io.write_all(&buf).await
    }

    async fn write_response<T>(
        &mut self,
        _: &libp2p::StreamProtocol,
        io: &mut T,
        res: Self::Response,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        use futures::AsyncWriteExt;
        let buf = bincode::serialize(&res)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        io.write_all(&(buf.len() as u32).to_le_bytes()).await?;
        io.write_all(&buf).await
    }
}
