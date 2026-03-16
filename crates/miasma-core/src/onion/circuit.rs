/// Circuit state management.
///
/// Every DHT query and every Share retrieval uses a **new** ephemeral circuit
/// so that an adversary observing multiple requests cannot link them to the
/// same initiator. This file owns that lifecycle.
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::{oneshot, Mutex};

use crate::MiasmaError;

use super::packet::{CircuitId, ReturnPath, X25519_KEY_LEN};

// ─── Relay descriptor ────────────────────────────────────────────────────────

/// Metadata about a known relay node.
#[derive(Debug, Clone)]
pub struct RelayInfo {
    /// Relay's peer ID bytes.
    pub peer_id: Vec<u8>,
    /// Relay's static X25519 public key (used for onion layer encryption).
    pub onion_pubkey: [u8; X25519_KEY_LEN],
    /// Relay's network address for forwarding packets.
    pub addr: Vec<u8>,
}

// ─── PendingCircuit ───────────────────────────────────────────────────────────

/// State tracked for an in-flight onion request.
struct PendingCircuit {
    return_path: ReturnPath,
    /// Channel to deliver the decrypted response to the waiting caller.
    response_tx: oneshot::Sender<Vec<u8>>,
    created_at: Instant,
}

// ─── CircuitManager ──────────────────────────────────────────────────────────

/// Tracks active onion circuits and routes incoming responses.
///
/// Lifecycle:
/// 1. Caller calls `register()` → gets `(circuit_id, response_rx)`.
/// 2. Caller builds `OnionPacket` with `circuit_id`.
/// 3. When a response arrives, caller calls `deliver_response(circuit_id, blob)`.
/// 4. `response_rx` resolves with the decrypted plaintext.
///
/// Circuits are garbage-collected after `TTL` even if no response arrives.
pub struct CircuitManager {
    pending: Arc<Mutex<HashMap<[u8; 16], PendingCircuit>>>,
    /// How long to keep an unanswered circuit alive.
    ttl: Duration,
}

impl CircuitManager {
    pub fn new(ttl: Duration) -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            ttl,
        }
    }

    /// Default TTL = 60 seconds (DHT query + relay round-trip budget).
    pub fn with_default_ttl() -> Self {
        Self::new(Duration::from_secs(60))
    }

    /// Register a new circuit.
    ///
    /// Returns `(circuit_id, response_rx)`.
    /// - Send the `OnionPacket` with `circuit_id` through the relay path.
    /// - Await `response_rx` to receive the decrypted response body.
    pub async fn register(
        &self,
        return_path: ReturnPath,
    ) -> (CircuitId, oneshot::Receiver<Vec<u8>>) {
        let circuit_id = return_path.circuit_id;
        let (tx, rx) = oneshot::channel();

        let mut pending = self.pending.lock().await;
        // Evict expired circuits before inserting.
        self.evict_expired(&mut pending);

        pending.insert(
            circuit_id.0,
            PendingCircuit {
                return_path,
                response_tx: tx,
                created_at: Instant::now(),
            },
        );

        (circuit_id, rx)
    }

    /// Deliver an encrypted response blob for a circuit.
    ///
    /// The manager decrypts through the return path and wakes the waiting caller.
    /// Returns `Ok(true)` if delivered, `Ok(false)` if circuit was unknown/expired.
    pub async fn deliver_response(
        &self,
        circuit_id: CircuitId,
        encrypted_blob: Vec<u8>,
    ) -> Result<bool, MiasmaError> {
        let mut pending = self.pending.lock().await;

        let entry = match pending.remove(&circuit_id.0) {
            Some(e) => e,
            None => return Ok(false),
        };

        // Decrypt: blob passed from R1 was encrypted with r1_init_key.
        let intermediate =
            super::packet::decrypt_response(&entry.return_path.r1_init_key, &encrypted_blob)?;

        // Decrypt again: the inner blob was encrypted with r2_r1_key.
        let plaintext =
            super::packet::decrypt_response(&entry.return_path.r2_r1_key, &intermediate)?;

        // Deliver to the waiting caller.
        let _ = entry.response_tx.send(plaintext);
        Ok(true)
    }

    /// Number of active (non-expired) circuits.
    pub async fn active_count(&self) -> usize {
        let pending = self.pending.lock().await;
        let now = Instant::now();
        pending
            .values()
            .filter(|c| now.duration_since(c.created_at) < self.ttl)
            .count()
    }

    // Evict entries older than TTL. Caller must hold the lock.
    fn evict_expired(&self, pending: &mut HashMap<[u8; 16], PendingCircuit>) {
        let now = Instant::now();
        pending.retain(|_, c| now.duration_since(c.created_at) < self.ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::packet::{encrypt_response, CircuitId};

    fn dummy_return_path() -> ReturnPath {
        let mut r2_r1_key = [0u8; 32];
        let mut r1_init_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut r2_r1_key);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut r1_init_key);
        ReturnPath {
            circuit_id: CircuitId::random(),
            r2_addr: b"addr".to_vec(),
            r2_r1_key,
            r1_init_key,
        }
    }

    #[tokio::test]
    async fn register_and_deliver() {
        let mgr = CircuitManager::with_default_ttl();
        let rp = dummy_return_path();
        let (cid, rx) = mgr.register(rp.clone()).await;
        assert_eq!(mgr.active_count().await, 1);

        let response_body = b"DHT result data".to_vec();
        let intermediate = encrypt_response(&rp.r2_r1_key, &response_body).unwrap();
        let blob = encrypt_response(&rp.r1_init_key, &intermediate).unwrap();
        let delivered = mgr.deliver_response(cid, blob).await.unwrap();
        assert!(delivered);

        let received = rx.await.unwrap();
        assert_eq!(received, response_body);
        assert_eq!(mgr.active_count().await, 0);
    }

    #[tokio::test]
    async fn unknown_circuit_returns_false() {
        let mgr = CircuitManager::with_default_ttl();
        let unknown = CircuitId::random();
        let result = mgr
            .deliver_response(unknown, vec![0u8; 40])
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn duplicate_register_overwrites() {
        let mgr = CircuitManager::with_default_ttl();
        let rp1 = dummy_return_path();
        let rp2 = ReturnPath {
            circuit_id: rp1.circuit_id, // same ID
            ..dummy_return_path()
        };
        mgr.register(rp1).await;
        mgr.register(rp2).await;
        // Should still be 1 (overwrote).
        assert_eq!(mgr.active_count().await, 1);
    }
}
