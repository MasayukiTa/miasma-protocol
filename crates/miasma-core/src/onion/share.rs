/// Onion-routed share fetching — Phase 1 (in-process simulation).
///
/// Mirrors `LiveOnionDhtExecutor` but serves `MiasmaShare` objects instead of
/// DHT records. Each `fetch_share` call uses an independent ephemeral onion
/// circuit (ADR-002 §share-fetch-privacy).
///
/// # Tag bytes
/// - `0x10` = ShareRequest
/// - `0x11` = ShareResponse
use std::{sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{share::MiasmaShare, store::LocalShareStore, MiasmaError};

use super::{
    circuit::{CircuitManager, RelayInfo},
    packet::{CircuitId, InnerPayload, OnionPacketBuilder},
    router::InProcessRelay,
};

// ─── Wire format ──────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub(crate) struct ShareRequest {
    pub mid_digest: [u8; 32],
    pub slot_index: u16,
    pub segment_index: u32,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ShareResponse {
    pub share: Option<MiasmaShare>,
}

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Abstraction over onion-routed share fetching.
///
/// Phase 1: `LiveOnionShareFetcher` — in-process relay, local store backend.
/// Phase 2: replaced by a network-routed implementation backed by remote peers.
#[async_trait::async_trait]
pub trait OnionShareFetcher: Send + Sync {
    async fn fetch_share(
        &self,
        mid_digest: [u8; 32],
        slot_index: u16,
        segment_index: u32,
    ) -> Result<Option<MiasmaShare>, MiasmaError>;
}

// ─── LiveOnionShareFetcher ────────────────────────────────────────────────────

/// Phase 1 share fetcher: routes requests through the 2-hop in-process relay,
/// backed by a `LocalShareStore`.
///
/// Each `fetch_share` call builds a new ephemeral onion circuit so that
/// concurrent or sequential requests for different shares cannot be correlated.
pub struct LiveOnionShareFetcher {
    circuit_manager: Arc<CircuitManager>,
    relay: Arc<InProcessRelayWrapper>,
    relay_dir: Arc<Mutex<Vec<RelayInfo>>>,
    store: Arc<LocalShareStore>,
}

enum InProcessRelayWrapper {
    InProcess {
        relay: InProcessRelay,
        payload_rx: Mutex<tokio::sync::mpsc::UnboundedReceiver<(CircuitId, InnerPayload)>>,
    },
}

impl LiveOnionShareFetcher {
    /// Create a Phase 1 fetcher backed by `store`, using simulated in-process relays.
    pub fn new_phase1(
        node_master_key: &[u8],
        store: Arc<LocalShareStore>,
    ) -> Result<Self, MiasmaError> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let derive = |label: &[u8]| -> Result<[u8; 32], MiasmaError> {
            let hk = Hkdf::<Sha256>::new(None, node_master_key);
            let mut out = [0u8; 32];
            hk.expand(label, &mut out)
                .map_err(|e| MiasmaError::KeyDerivation(e.to_string()))?;
            Ok(out)
        };

        let r1_secret = derive(b"miasma-sim-relay1-x25519-v1")?;
        let r2_secret = derive(b"miasma-sim-relay2-x25519-v1")?;

        let r1_pubkey = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(r1_secret));
        let r2_pubkey = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(r2_secret));

        let relay_dir = vec![
            RelayInfo {
                peer_id: b"sim-relay-1".to_vec(),
                onion_pubkey: r1_pubkey.to_bytes(),
                addr: b"inprocess://relay1".to_vec(),
            },
            RelayInfo {
                peer_id: b"sim-relay-2".to_vec(),
                onion_pubkey: r2_pubkey.to_bytes(),
                addr: b"inprocess://relay2".to_vec(),
            },
        ];

        let (relay, payload_rx) = InProcessRelay::new(r1_secret, r2_secret);
        let circuit_manager = Arc::new(CircuitManager::new(Duration::from_secs(30)));

        Ok(Self {
            circuit_manager,
            relay: Arc::new(InProcessRelayWrapper::InProcess {
                relay,
                payload_rx: Mutex::new(payload_rx),
            }),
            relay_dir: Arc::new(Mutex::new(relay_dir)),
            store,
        })
    }

    async fn process_one_payload(&self) -> Result<(), MiasmaError> {
        let InProcessRelayWrapper::InProcess { payload_rx, .. } = self.relay.as_ref();
        let mut rx = payload_rx.lock().await;

        let (_, inner) = rx
            .recv()
            .await
            .ok_or_else(|| MiasmaError::Sss("relay channel closed".into()))?;

        let return_path = inner.return_path.clone();
        let response_bytes = self.handle_share_payload(&inner.body).await?;

        InProcessRelay::route_response(self.circuit_manager.clone(), &return_path, response_bytes)
            .await
    }

    async fn handle_share_payload(&self, body: &[u8]) -> Result<Vec<u8>, MiasmaError> {
        if body.is_empty() {
            return Err(MiasmaError::Sss("empty share payload".into()));
        }
        match body[0] {
            0x10 => {
                let req: ShareRequest = bincode::deserialize(&body[1..])
                    .map_err(|e| MiasmaError::Serialization(e.to_string()))?;

                // Search local store for the requested shard.
                let prefix: [u8; 8] = req.mid_digest[..8].try_into().unwrap();
                let candidates = self.store.search_by_mid_prefix(&prefix);

                let share = candidates.iter().find_map(|addr| {
                    self.store.get(addr).ok().and_then(|s| {
                        if s.slot_index == req.slot_index && s.segment_index == req.segment_index {
                            Some(s)
                        } else {
                            None
                        }
                    })
                });

                let resp = ShareResponse { share };
                let mut out = vec![0x11u8];
                out.extend(
                    bincode::serialize(&resp)
                        .map_err(|e| MiasmaError::Serialization(e.to_string()))?,
                );
                Ok(out)
            }
            tag => Err(MiasmaError::Sss(format!(
                "unknown share payload tag: {tag}"
            ))),
        }
    }

    async fn send_onion_query(&self, body: Vec<u8>) -> Result<Vec<u8>, MiasmaError> {
        let dir = self.relay_dir.lock().await;
        if dir.len() < 2 {
            return Err(MiasmaError::Sss("need >=2 relays for 2-hop circuit".into()));
        }
        let r1 = &dir[0];
        let r2 = &dir[1];

        let (packet, return_path) = OnionPacketBuilder::build(
            &r1.onion_pubkey,
            &r2.onion_pubkey,
            r2.peer_id.clone(),
            b"share-target".to_vec(),
            r2.addr.clone(),
            body,
        )?;
        drop(dir);

        let (_, rx) = self.circuit_manager.register(return_path).await;

        let InProcessRelayWrapper::InProcess { relay, .. } = self.relay.as_ref();
        relay.forward(&packet)?;

        self.process_one_payload().await?;

        rx.await
            .map_err(|_| MiasmaError::Sss("circuit response channel dropped".into()))
    }
}

#[async_trait::async_trait]
impl OnionShareFetcher for LiveOnionShareFetcher {
    async fn fetch_share(
        &self,
        mid_digest: [u8; 32],
        slot_index: u16,
        segment_index: u32,
    ) -> Result<Option<MiasmaShare>, MiasmaError> {
        let req = ShareRequest {
            mid_digest,
            slot_index,
            segment_index,
        };
        let body_inner =
            bincode::serialize(&req).map_err(|e| MiasmaError::Serialization(e.to_string()))?;
        let mut body = vec![0x10u8]; // ShareRequest tag
        body.extend(body_inner);

        let resp = self.send_onion_query(body).await?;
        if resp.first() != Some(&0x11) {
            return Err(MiasmaError::Sss("unexpected share response tag".into()));
        }
        let response: ShareResponse = bincode::deserialize(&resp[1..])
            .map_err(|e| MiasmaError::Serialization(e.to_string()))?;
        Ok(response.share)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pipeline::dissolve, pipeline::DissolutionParams};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn make_store(dir: &TempDir) -> Arc<LocalShareStore> {
        Arc::new(LocalShareStore::open(dir.path(), 100).unwrap())
    }

    #[tokio::test]
    async fn fetch_existing_share_via_onion() {
        let master = [0x55u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let store = make_store(&dir);

        let content = b"onion share fetch test";
        let params = DissolutionParams::default();
        let (mid, shares) = dissolve(content, params).unwrap();

        for s in &shares {
            store.put(s).unwrap();
        }

        let fetcher = LiveOnionShareFetcher::new_phase1(&master, store).unwrap();

        // Fetch the first share (slot 0, segment 0).
        let result = fetcher.fetch_share(*mid.as_bytes(), 0, 0).await.unwrap();
        assert!(result.is_some(), "slot 0 should be found");
        let share = result.unwrap();
        assert_eq!(share.slot_index, 0);
        assert_eq!(share.segment_index, 0);
        assert_eq!(share.mid_prefix, mid.prefix());
    }

    #[tokio::test]
    async fn fetch_missing_share_returns_none() {
        let master = [0x66u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let store = make_store(&dir);
        let fetcher = LiveOnionShareFetcher::new_phase1(&master, store).unwrap();

        // No shares stored — should return None.
        let mid_digest = [0xAAu8; 32];
        let result = fetcher.fetch_share(mid_digest, 0, 0).await.unwrap();
        assert!(result.is_none());
    }
}
