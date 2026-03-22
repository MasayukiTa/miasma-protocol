/// Onion relay protocol — `/miasma/onion/1.0.0`.
///
/// # Wire protocol
///
/// The onion relay protocol provides 2-hop per-hop encrypted retrieval.
/// Each relay node peels one onion layer using its X25519 static key,
/// extracts a per-hop return key for response encryption, and forwards
/// the inner encrypted blob to the next hop.
///
/// # Request flow
/// ```text
/// Initiator ──OnionPacket──▶ R1 ──ForwardCell──▶ R2 ──ShareFetch──▶ Target
///           ◀──encrypted────────◀──encrypted──────◀──plaintext──────
/// ```
///
/// Each relay encrypts the response with its per-hop return_key before
/// forwarding back, so the initiator receives a doubly-encrypted response
/// that it decrypts with the keys it generated during packet construction.
///
/// # Content privacy
///
/// The share-fetch body is additionally end-to-end encrypted for the target
/// using X25519 ECDH, so neither relay can read the actual share request
/// or response content.
use serde::{Deserialize, Serialize};

use crate::onion::packet::{CircuitId, OnionLayer};

/// Max message size for onion relay protocol (64 KiB — onion packets are multi-layered).
pub const ONION_MSG_MAX: usize = 64 * 1024;

// ─── Wire types ──────────────────────────────────────────────────────────────

/// Request sent over the `/miasma/onion/1.0.0` protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OnionRelayRequest {
    /// Initial onion packet from Initiator → R1.
    /// R1 peels the outer layer and forwards the inner as a Forward variant.
    Packet {
        circuit_id: CircuitId,
        layer: OnionLayer,
    },
    /// Forwarded cell from R1 → R2.
    /// R2 peels the inner layer, extracts target and body.
    Forward {
        circuit_id: CircuitId,
        layer: OnionLayer,
    },
    /// Final delivery from R2 → Target.
    /// Target decrypts the e2e-encrypted body and processes the share request.
    Deliver {
        circuit_id: CircuitId,
        /// The e2e-encrypted body (target decrypts with its onion static key).
        body: Vec<u8>,
    },
}

/// Response sent back through the onion path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OnionRelayResponse {
    /// Encrypted response data.
    /// Each relay adds a layer of encryption with its return_key.
    Data(Vec<u8>),
    /// Error — request could not be processed.
    Error(String),
}

// ─── Codec ───────────────────────────────────────────────────────────────────

/// Bincode + 4-byte LE length-prefix codec for `/miasma/onion/1.0.0`.
#[derive(Clone, Default)]
pub struct OnionRelayCodec;

#[async_trait::async_trait]
impl libp2p::request_response::Codec for OnionRelayCodec {
    type Protocol = libp2p::StreamProtocol;
    type Request = OnionRelayRequest;
    type Response = OnionRelayResponse;

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
        if len > ONION_MSG_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "onion relay msg too large",
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
        if len > ONION_MSG_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "onion relay response too large",
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

// ─── Relay handler logic ─────────────────────────────────────────────────────

/// Result of processing an onion relay request at a relay node.
pub enum OnionRelayAction {
    /// Forward the inner layer to the next hop (R1 → R2).
    ForwardToNext {
        next_hop_peer_id: Vec<u8>,
        circuit_id: CircuitId,
        inner_layer: OnionLayer,
        /// Per-hop return key — the relay encrypts the response with this
        /// before returning it to the previous hop.
        return_key: [u8; 32],
    },
    /// Deliver the body to the target (R2 → Target).
    DeliverToTarget {
        target_peer_id: Vec<u8>,
        circuit_id: CircuitId,
        body: Vec<u8>,
        /// Per-hop return key for this relay.
        return_key: [u8; 32],
    },
}

/// Process an incoming onion layer at a relay node.
///
/// Peels one encryption layer using the relay's X25519 static secret and
/// returns the action to take: forward to the next relay or deliver to target.
pub fn process_onion_layer(
    relay_static_secret: &[u8; 32],
    circuit_id: CircuitId,
    layer: &OnionLayer,
) -> Result<OnionRelayAction, crate::MiasmaError> {
    use crate::onion::packet::OnionLayerProcessor;

    let payload = OnionLayerProcessor::peel(relay_static_secret, layer)?;

    let next_hop = payload
        .next_hop
        .ok_or_else(|| crate::MiasmaError::Sss("relay received a layer with no next_hop".into()))?;

    let return_key = payload
        .return_key
        .ok_or_else(|| crate::MiasmaError::Sss("relay layer missing return_key".into()))?;

    // Try to deserialize the data as an inner OnionLayer.
    // If it deserializes, this is an intermediate hop (R1) — forward to next relay.
    // If not, this is the exit relay (R2) — deliver the raw body to the target.
    match bincode::deserialize::<OnionLayer>(&payload.data) {
        Ok(inner_layer) => Ok(OnionRelayAction::ForwardToNext {
            next_hop_peer_id: next_hop,
            circuit_id,
            inner_layer,
            return_key,
        }),
        Err(_) => {
            // R2 position: the data is the InnerPayload, extract the body.
            // For e2e encrypted mode, the body contains session_key || e2e_blob.
            // We pass through the raw data — the target decrypts.
            let inner: crate::onion::packet::InnerPayload = bincode::deserialize(&payload.data)
                .map_err(|e| {
                    crate::MiasmaError::Serialization(format!(
                        "relay: failed to parse inner payload: {e}"
                    ))
                })?;
            Ok(OnionRelayAction::DeliverToTarget {
                target_peer_id: next_hop,
                circuit_id,
                body: inner.body,
                return_key,
            })
        }
    }
}

/// Encrypt a response blob with a per-hop return key (XChaCha20-Poly1305).
pub fn encrypt_relay_response(
    return_key: &[u8; 32],
    response: &[u8],
) -> Result<Vec<u8>, crate::MiasmaError> {
    crate::onion::packet::encrypt_response(return_key, response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::packet::{OnionPacketBuilder, X25519_KEY_LEN};
    use x25519_dalek::{PublicKey, StaticSecret};

    fn make_keypair() -> ([u8; X25519_KEY_LEN], [u8; X25519_KEY_LEN]) {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pubkey = PublicKey::from(&secret);
        (secret.to_bytes(), pubkey.to_bytes())
    }

    #[test]
    fn process_onion_layer_r1_forwards() {
        let (r1_sec, r1_pub) = make_keypair();
        let (_r2_sec, r2_pub) = make_keypair();

        let (packet, _rp) = OnionPacketBuilder::build(
            &r1_pub,
            &r2_pub,
            b"r2_peer".to_vec(),
            b"target".to_vec(),
            b"r2_addr".to_vec(),
            b"test body".to_vec(),
        )
        .unwrap();

        let action = process_onion_layer(&r1_sec, packet.circuit_id, &packet.layer).unwrap();

        match action {
            OnionRelayAction::ForwardToNext {
                next_hop_peer_id,
                return_key,
                ..
            } => {
                assert_eq!(next_hop_peer_id, b"r2_peer");
                assert_ne!(return_key, [0u8; 32]); // non-zero return key
            }
            _ => panic!("expected ForwardToNext"),
        }
    }

    #[test]
    fn process_onion_layer_r2_delivers() {
        let (r1_sec, r1_pub) = make_keypair();
        let (r2_sec, r2_pub) = make_keypair();

        let body = b"share fetch request".to_vec();
        let (packet, _rp) = OnionPacketBuilder::build(
            &r1_pub,
            &r2_pub,
            b"r2_peer".to_vec(),
            b"target".to_vec(),
            b"r2_addr".to_vec(),
            body.clone(),
        )
        .unwrap();

        // R1 peels
        let action1 = process_onion_layer(&r1_sec, packet.circuit_id, &packet.layer).unwrap();
        let (inner_layer, r1_return_key) = match action1 {
            OnionRelayAction::ForwardToNext {
                inner_layer,
                return_key,
                ..
            } => (inner_layer, return_key),
            _ => panic!("expected ForwardToNext"),
        };

        // R2 peels
        let action2 = process_onion_layer(&r2_sec, packet.circuit_id, &inner_layer).unwrap();
        match action2 {
            OnionRelayAction::DeliverToTarget {
                target_peer_id,
                body: delivered_body,
                return_key: r2_return_key,
                ..
            } => {
                assert_eq!(target_peer_id, b"target");
                assert_eq!(delivered_body, body);
                assert_ne!(r2_return_key, r1_return_key); // different per-hop keys
            }
            _ => panic!("expected DeliverToTarget"),
        }
    }

    #[test]
    fn response_encryption_layering() {
        let (r1_sec, r1_pub) = make_keypair();
        let (r2_sec, r2_pub) = make_keypair();

        let (packet, _rp) = OnionPacketBuilder::build(
            &r1_pub,
            &r2_pub,
            b"r2_peer".to_vec(),
            b"target".to_vec(),
            b"r2_addr".to_vec(),
            b"query".to_vec(),
        )
        .unwrap();

        // R1 peels → get r1_return_key
        let action1 = process_onion_layer(&r1_sec, packet.circuit_id, &packet.layer).unwrap();
        let (inner_layer, r1_return_key) = match action1 {
            OnionRelayAction::ForwardToNext {
                inner_layer,
                return_key,
                ..
            } => (inner_layer, return_key),
            _ => panic!("expected ForwardToNext"),
        };

        // R2 peels → get r2_return_key
        let action2 = process_onion_layer(&r2_sec, packet.circuit_id, &inner_layer).unwrap();
        let r2_return_key = match action2 {
            OnionRelayAction::DeliverToTarget { return_key, .. } => return_key,
            _ => panic!("expected DeliverToTarget"),
        };

        // Target produces plaintext response
        let response = b"share data payload".to_vec();

        // R2 encrypts with r2_return_key
        let r2_encrypted = encrypt_relay_response(&r2_return_key, &response).unwrap();

        // R1 encrypts with r1_return_key
        let r1_encrypted = encrypt_relay_response(&r1_return_key, &r2_encrypted).unwrap();

        // Initiator decrypts: r1 layer first, then r2 layer
        let after_r1 =
            crate::onion::packet::decrypt_response(&r1_return_key, &r1_encrypted).unwrap();
        let plaintext = crate::onion::packet::decrypt_response(&r2_return_key, &after_r1).unwrap();

        assert_eq!(plaintext, response);
    }

    #[test]
    fn e2e_encrypted_build_and_relay_delivery() {
        let (r1_sec, r1_pub) = make_keypair();
        let (r2_sec, r2_pub) = make_keypair();
        let (target_sec, target_pub) = make_keypair();

        let body = b"secret share request".to_vec();
        let (packet, _rp, session_key) = OnionPacketBuilder::build_e2e(
            &r1_pub,
            &r2_pub,
            &target_pub,
            b"r2_peer".to_vec(),
            b"target".to_vec(),
            b"r2_addr".to_vec(),
            body.clone(),
        )
        .unwrap();

        // R1 peels
        let action1 = process_onion_layer(&r1_sec, packet.circuit_id, &packet.layer).unwrap();
        let inner_layer = match action1 {
            OnionRelayAction::ForwardToNext { inner_layer, .. } => inner_layer,
            _ => panic!("expected ForwardToNext"),
        };

        // R2 peels — gets the body but can't read it (e2e encrypted)
        let action2 = process_onion_layer(&r2_sec, packet.circuit_id, &inner_layer).unwrap();
        let delivered_body = match action2 {
            OnionRelayAction::DeliverToTarget { body, .. } => body,
            _ => panic!("expected DeliverToTarget"),
        };

        // Delivered body = session_key(32) || e2e_layer_bytes
        assert!(delivered_body.len() > 32);
        let recv_session_key: [u8; 32] = delivered_body[..32].try_into().unwrap();
        assert_eq!(recv_session_key, *session_key);

        // Target decrypts the e2e layer
        let e2e_layer: crate::onion::packet::OnionLayer =
            bincode::deserialize(&delivered_body[32..]).unwrap();
        let e2e_payload =
            crate::onion::packet::OnionLayerProcessor::peel(&target_sec, &e2e_layer).unwrap();
        assert!(e2e_payload.next_hop.is_none()); // final destination
        assert_eq!(e2e_payload.data, body);
    }
}
