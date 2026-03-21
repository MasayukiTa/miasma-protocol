/// Relay probe protocol — `/miasma/relay-probe/1.0.0`.
///
/// # Purpose
///
/// Active relay verification that goes beyond descriptor claims and passive
/// observation. A relay probe sends a random nonce to a candidate relay peer;
/// if the peer echoes the nonce back, we know:
///
/// 1. The peer runs the relay probe protocol
/// 2. The peer is reachable at its advertised address
/// 3. The peer is responsive (not just a stale descriptor claim)
///
/// A successful probe counts as a relay observation, promoting the peer's
/// `RelayTrustTier` from `Claimed` toward `Observed` and eventually `Verified`.
///
/// # Limits
///
/// A probe verifies reachability and protocol support, but does NOT verify
/// that the peer actually forwards traffic to third parties. Full forwarding
/// verification would require a cooperative third party and is deferred.
///
/// # Wire protocol
///
/// Simple request-response: `ProbeRequest { nonce }` → `ProbeResponse { nonce }`.
/// The relay echoes the nonce unchanged. The prober verifies the match.
use serde::{Deserialize, Serialize};

/// Max message size for relay probe protocol (256 bytes — very lightweight).
pub const PROBE_MSG_MAX: usize = 256;

// ─── Wire types ──────────────────────────────────────────────────────────────

/// Challenge sent to a relay candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeRequest {
    /// Random nonce — the relay must echo this back.
    pub nonce: [u8; 32],
}

/// Echo response from the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResponse {
    /// Must equal the request nonce for verification.
    pub nonce: [u8; 32],
}

// ─── Codec ───────────────────────────────────────────────────────────────────

/// Bincode + 4-byte LE length-prefix codec for `/miasma/relay-probe/1.0.0`.
#[derive(Clone, Default)]
pub struct RelayProbeCodec;

#[async_trait::async_trait]
impl libp2p::request_response::Codec for RelayProbeCodec {
    type Protocol = libp2p::StreamProtocol;
    type Request = ProbeRequest;
    type Response = ProbeResponse;

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
        if len > PROBE_MSG_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "relay probe request too large",
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
        if len > PROBE_MSG_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "relay probe response too large",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_request_roundtrip() {
        let nonce = [0xABu8; 32];
        let req = ProbeRequest { nonce };
        let bytes = bincode::serialize(&req).unwrap();
        let decoded: ProbeRequest = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.nonce, nonce);
    }

    #[test]
    fn probe_response_roundtrip() {
        let nonce = [0xCDu8; 32];
        let resp = ProbeResponse { nonce };
        let bytes = bincode::serialize(&resp).unwrap();
        let decoded: ProbeResponse = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.nonce, nonce);
    }
}
