/// Onion relay logic and in-process simulation.
///
/// # Production path (Phase 2+)
/// Real relay nodes run `OnionRelayHandler::handle_forward_cell()` when they
/// receive packets from the network. The handler peels one layer and forwards
/// the inner payload to the next hop via libp2p.
///
/// # Phase 1 in-process simulation
/// `InProcessRelay` wires two `OnionRelayHandler` instances together in memory,
/// allowing full onion round-trips (including response path) to be tested
/// without a real network.
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::debug;

use crate::MiasmaError;

use super::{
    circuit::CircuitManager,
    packet::{
        encrypt_response, CircuitId, InnerPayload, OnionLayer,
        OnionLayerProcessor, OnionPacket, ReturnPath, X25519_KEY_LEN,
    },
};

// ─── Wire message types ───────────────────────────────────────────────────────

/// A forwarded onion cell (after outer layer was stripped by Relay1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardCell {
    pub circuit_id: CircuitId,
    /// The inner onion layer (encrypted for Relay2).
    pub layer: OnionLayer,
}

/// A response cell travelling back toward the initiator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseCell {
    pub circuit_id: CircuitId,
    /// XChaCha20-Poly1305 encrypted response body.
    /// Encrypted with `return_path.r2_r1_key` (R2→R1 leg)
    /// or `return_path.r1_init_key` (R1→Initiator leg).
    pub encrypted_body: Vec<u8>,
}

// ─── OnionRelayHandler ────────────────────────────────────────────────────────

/// Handles onion cells at a single relay node.
///
/// Each relay has a static X25519 identity used to peel incoming layers.
pub struct OnionRelayHandler {
    /// This relay's static X25519 private key.
    relay_secret: [u8; X25519_KEY_LEN],
}

impl OnionRelayHandler {
    pub fn new(relay_secret: [u8; X25519_KEY_LEN]) -> Self {
        Self { relay_secret }
    }

    /// Process an incoming `OnionPacket` at Relay1.
    ///
    /// Returns `(next_hop_id, ForwardCell)` — the caller should send
    /// `ForwardCell` to `next_hop_id` via the transport layer.
    pub fn handle_packet(
        &self,
        packet: &OnionPacket,
    ) -> Result<(Vec<u8>, ForwardCell), MiasmaError> {
        let payload = OnionLayerProcessor::peel(&self.relay_secret, &packet.layer)?;

        let next_hop = payload.next_hop.ok_or_else(|| {
            MiasmaError::Sss("Relay1 got a packet with no next_hop".into())
        })?;

        // Deserialise the inner layer (encrypted for Relay2).
        let inner_layer: OnionLayer = bincode::deserialize(&payload.data)
            .map_err(|e| MiasmaError::Serialization(e.to_string()))?;

        Ok((
            next_hop,
            ForwardCell {
                circuit_id: packet.circuit_id,
                layer: inner_layer,
            },
        ))
    }

    /// Process an incoming `ForwardCell` at Relay2.
    ///
    /// Returns `(target_peer_id, inner_payload)` — the caller sends the
    /// `InnerPayload.body` to `target_peer_id` together with the ReturnPath.
    pub fn handle_forward_cell(
        &self,
        cell: &ForwardCell,
    ) -> Result<(Vec<u8>, InnerPayload), MiasmaError> {
        let payload = OnionLayerProcessor::peel(&self.relay_secret, &cell.layer)?;

        let target = payload.next_hop.ok_or_else(|| {
            MiasmaError::Sss("Relay2 got a ForwardCell with no next_hop".into())
        })?;

        let inner: InnerPayload = bincode::deserialize(&payload.data)
            .map_err(|e| MiasmaError::Serialization(e.to_string()))?;

        Ok((target, inner))
    }
}

// ─── InProcessRelay ──────────────────────────────────────────────────────────

/// Simulates the full 2-hop relay path in-process for Phase 1 testing.
///
/// **No anonymity is provided** — this is purely for correctness testing.
/// The actual relay forwarding is implemented in Phase 2 network integration.
///
/// # Architecture
/// ```text
/// send_request()
///     → Relay1.handle_packet()         (peel outer layer)
///     → Relay2.handle_forward_cell()   (peel inner layer)
///     → inner_payload delivered to caller via mpsc channel
///
/// send_response(circuit_id, response_body)
///     → encrypt with r2_r1_key
///     → encrypt again with r1_init_key
///     → CircuitManager.deliver_response()
/// ```
pub struct InProcessRelay {
    relay1: OnionRelayHandler,
    relay2: OnionRelayHandler,
    /// Receives (circuit_id, inner_payload) pairs when packets reach the target.
    payload_tx: mpsc::UnboundedSender<(CircuitId, InnerPayload)>,
}

impl InProcessRelay {
    pub fn new(
        r1_secret: [u8; X25519_KEY_LEN],
        r2_secret: [u8; X25519_KEY_LEN],
    ) -> (Self, mpsc::UnboundedReceiver<(CircuitId, InnerPayload)>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let relay = Self {
            relay1: OnionRelayHandler::new(r1_secret),
            relay2: OnionRelayHandler::new(r2_secret),
            payload_tx: tx,
        };
        (relay, rx)
    }

    /// Forward an `OnionPacket` through R1 → R2 → (deliver to receiver).
    pub fn forward(&self, packet: &OnionPacket) -> Result<(), MiasmaError> {
        debug!("InProcessRelay: forwarding circuit {:?}", packet.circuit_id);

        // R1 peels outer layer.
        let (_next_hop_r2, forward_cell) = self.relay1.handle_packet(packet)?;

        // R2 peels inner layer.
        let (_target, inner_payload) = self.relay2.handle_forward_cell(&forward_cell)?;

        // Deliver to the "target" (in-process consumer).
        self.payload_tx
            .send((packet.circuit_id, inner_payload))
            .map_err(|_| MiasmaError::Sss("InProcessRelay: payload channel closed".into()))?;

        Ok(())
    }

    /// Simulate a response from Target back to Initiator.
    ///
    /// `return_path` comes from the `InnerPayload` the target received.
    /// Encrypts the response through R2→R1→Initiator legs and delivers via
    /// `circuit_manager`.
    pub async fn route_response(
        circuit_manager: Arc<CircuitManager>,
        return_path: &ReturnPath,
        response_body: Vec<u8>,
    ) -> Result<(), MiasmaError> {
        // R2 → R1 leg: encrypt with r2_r1_key.
        let r2_r1_encrypted = encrypt_response(&return_path.r2_r1_key, &response_body)?;

        // R1 → Initiator leg: encrypt again with r1_init_key.
        let r1_init_encrypted =
            encrypt_response(&return_path.r1_init_key, &r2_r1_encrypted)?;

        // Deliver to the waiting circuit (CircuitManager decrypts the outer layer).
        circuit_manager
            .deliver_response(return_path.circuit_id, r1_init_encrypted)
            .await?;

        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::packet::OnionPacketBuilder;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn make_relay() -> ([u8; 32], [u8; 32]) {
        let sec = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pub_ = PublicKey::from(&sec);
        (sec.to_bytes(), pub_.to_bytes())
    }

    #[tokio::test]
    async fn full_round_trip_in_process() {
        let (r1_sec, r1_pub) = make_relay();
        let (r2_sec, r2_pub) = make_relay();

        let query_body = b"get MID miasma:abc".to_vec();

        let (packet, return_path) = OnionPacketBuilder::build(
            &r1_pub,
            &r2_pub,
            b"r2_peer".to_vec(),
            b"dht_target".to_vec(),
            b"r2_addr".to_vec(),
            query_body.clone(),
        )
        .unwrap();

        let circuit_mgr = Arc::new(CircuitManager::with_default_ttl());

        // Register circuit BEFORE forwarding so response can be delivered.
        let (_, rx) = circuit_mgr.register(return_path.clone()).await;

        // Create relay and forward packet.
        let (relay, mut payload_rx) = InProcessRelay::new(r1_sec, r2_sec);
        relay.forward(&packet).unwrap();

        // "Target" receives the inner payload.
        let (circuit_id, inner) = payload_rx.recv().await.unwrap();
        assert_eq!(circuit_id, packet.circuit_id);
        assert_eq!(inner.body, query_body);

        // Target sends response back.
        let response = b"DHT record found".to_vec();
        InProcessRelay::route_response(circuit_mgr.clone(), &inner.return_path, response.clone())
            .await
            .unwrap();

        // Initiator receives decrypted response.
        let received = rx.await.unwrap();
        assert_eq!(received, response);
    }

    #[tokio::test]
    async fn wrong_relay_key_fails() {
        let (_r1_sec, r1_pub) = make_relay();
        let (r2_sec, r2_pub) = make_relay();

        let (packet, _) = OnionPacketBuilder::build(
            &r1_pub,
            &r2_pub,
            b"r2".to_vec(),
            b"target".to_vec(),
            b"addr".to_vec(),
            b"payload".to_vec(),
        )
        .unwrap();

        // Swap secrets: use r2_sec for R1 position (wrong key).
        let bad_r1 = OnionRelayHandler::new(r2_sec);
        assert!(bad_r1.handle_packet(&packet).is_err());
    }
}
