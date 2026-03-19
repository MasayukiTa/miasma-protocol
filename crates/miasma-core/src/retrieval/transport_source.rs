/// FallbackShareSource — retrieval source that uses the payload transport
/// fallback engine to fetch shares across multiple transport strategies.
///
/// This replaces `DhtShareSource` + `NetworkShareFetcher` as the production
/// `ShareSource` for network retrieval, adding:
/// - Multi-transport fallback (libp2p → TCP → WSS → relay)
/// - Per-share transport attempt recording
/// - Aggregate transport statistics
///
/// # Flow
/// ```text
/// FallbackShareSource::list_candidates(mid)
///   └─ DHT lookup → DhtRecord → locator strings
///
/// FallbackShareSource::fetch(locator)
///   └─ parse locator → peer_addr, slot, segment
///   └─ PayloadTransportSelector::fetch_share(peer_addr, ...)
///       ├─ try DirectLibp2p → failed
///       ├─ try TcpDirect    → success → return share
///       └─ record all attempts
/// ```
use std::sync::{Arc, Mutex};

use crate::{
    crypto::hash::ContentId,
    network::dht::OnionAwareDhtExecutor,
    share::MiasmaShare,
    transport::payload::{
        PayloadTransportSelector, TransportAttempt, TransportExhaustedError,
    },
    MiasmaError,
};

use super::source::ShareSource;

/// Share source that uses the payload transport fallback engine.
pub struct FallbackShareSource<D> {
    dht: D,
    transport_selector: Arc<PayloadTransportSelector>,
    /// Accumulated transport attempts across all fetches (for diagnostics).
    all_attempts: Mutex<Vec<TransportAttempt>>,
}

impl<D: OnionAwareDhtExecutor> FallbackShareSource<D> {
    pub fn new(dht: D, transport_selector: Arc<PayloadTransportSelector>) -> Self {
        Self {
            dht,
            transport_selector,
            all_attempts: Mutex::new(Vec::new()),
        }
    }

    /// Return all transport attempts accumulated during retrieval.
    /// Useful for post-retrieval diagnostics.
    pub fn drain_attempts(&self) -> Vec<TransportAttempt> {
        let mut attempts = self.all_attempts.lock().unwrap();
        std::mem::take(&mut *attempts)
    }
}

#[async_trait::async_trait]
impl<D: OnionAwareDhtExecutor> ShareSource for FallbackShareSource<D> {
    /// Query the DHT for a record matching `mid`, then enumerate shard locators.
    ///
    /// Locator format: `"{mid_hex}|{slot_index}|{segment_index}|{peer_id_hex}|{addr1},{addr2},..."`
    /// The peer info is extracted from DhtRecord.locations so transports
    /// don't need a redundant DHT lookup.
    async fn list_candidates(&self, mid: &ContentId) -> Vec<String> {
        match self.dht.get(mid).await {
            Ok(Some(record)) => {
                let mid_hex = hex::encode(record.mid_digest);
                record
                    .locations
                    .iter()
                    .map(|loc| {
                        let peer_id_hex = hex::encode(&loc.peer_id_bytes);
                        let addrs = loc.addrs.join(",");
                        format!(
                            "{}|{}|0|{}|{}",
                            mid_hex, loc.shard_index, peer_id_hex, addrs
                        )
                    })
                    .collect()
            }
            Ok(None) | Err(_) => vec![],
        }
    }

    /// Decode a locator and fetch the corresponding share via the transport
    /// fallback engine.
    ///
    /// Locator format: `"{mid_hex}|{slot_index}|{segment_index}|{peer_id_hex}|{addrs}"`
    async fn fetch(&self, locator: &str) -> Result<Option<MiasmaShare>, MiasmaError> {
        let parts: Vec<&str> = locator.splitn(5, '|').collect();
        if parts.len() < 3 {
            return Err(MiasmaError::InvalidMid(format!(
                "malformed locator: '{locator}'"
            )));
        }

        let mid_bytes =
            hex::decode(parts[0]).map_err(|e| MiasmaError::InvalidMid(e.to_string()))?;
        let mid_digest: [u8; 32] = mid_bytes
            .try_into()
            .map_err(|_| MiasmaError::InvalidMid("locator mid_hex must be 32 bytes".into()))?;

        let slot_index: u16 = parts[1]
            .parse()
            .map_err(|e: std::num::ParseIntError| MiasmaError::InvalidMid(e.to_string()))?;

        let segment_index: u32 = parts[2]
            .parse()
            .map_err(|e: std::num::ParseIntError| MiasmaError::InvalidMid(e.to_string()))?;

        // peer_addr carries the first listen address from the locator.
        let peer_addr = if parts.len() >= 5 {
            parts[4].split(',').next().unwrap_or("")
        } else {
            ""
        };

        match self
            .transport_selector
            .fetch_share(peer_addr, mid_digest, slot_index, segment_index)
            .await
        {
            Ok(result) => {
                // Record all attempts.
                let mut all = self.all_attempts.lock().unwrap();
                all.extend(result.attempts);
                Ok(Some(result.share))
            }
            Err(TransportExhaustedError { attempts }) => {
                // Check if this was a "share not found" (transport succeeded but share absent)
                let share_not_found = attempts.iter().any(|a| {
                    a.succeeded && a.error.as_deref() == Some("share not found on peer")
                });
                let mut all = self.all_attempts.lock().unwrap();
                all.extend(attempts);
                if share_not_found {
                    Ok(None) // Peer doesn't have the share — not a transport failure.
                } else {
                    // All transports failed — return None so coordinator tries next candidate.
                    // The attempts are recorded for post-retrieval diagnostics.
                    Ok(None)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        network::dht::BypassOnionDhtExecutor,
        network::types::DhtRecord,
        pipeline::{dissolve, DissolutionParams},
        transport::payload::{
            PayloadTransport, PayloadTransportError, PayloadTransportKind, TransportPhase,
        },
    };

    /// Mock transport that returns shares from a local store.
    struct MockLocalTransport {
        store: Arc<crate::store::LocalShareStore>,
    }

    #[async_trait::async_trait]
    impl PayloadTransport for MockLocalTransport {
        fn kind(&self) -> PayloadTransportKind {
            PayloadTransportKind::DirectLibp2p
        }

        async fn fetch_share(
            &self,
            _peer_addr: &str,
            mid_digest: [u8; 32],
            slot_index: u16,
            segment_index: u32,
        ) -> Result<Option<MiasmaShare>, PayloadTransportError> {
            let prefix: [u8; 8] = mid_digest[..8].try_into().unwrap();
            let candidates = self.store.search_by_mid_prefix(&prefix);
            let share = candidates.iter().find_map(|addr| {
                self.store.get(addr).ok().and_then(|s| {
                    if s.slot_index == slot_index && s.segment_index == segment_index {
                        Some(s)
                    } else {
                        None
                    }
                })
            });
            Ok(share)
        }
    }

    #[tokio::test]
    async fn fallback_source_retrieves_via_transport() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(crate::store::LocalShareStore::open(dir.path(), 100).unwrap());

        let params = DissolutionParams::default();
        let (mid, shares) = dissolve(b"fallback source test", params).unwrap();
        for s in &shares {
            store.put(s).unwrap();
        }

        // Set up DHT with a record.
        let dht = BypassOnionDhtExecutor::new();
        let record = DhtRecord {
            mid_digest: *mid.as_bytes(),
            data_shards: params.data_shards as u8,
            total_shards: params.total_shards as u8,
            version: 1,
            locations: (0..params.total_shards as u16)
                .map(|i| crate::network::types::ShardLocation {
                    peer_id_bytes: vec![0; 38],
                    shard_index: i,
                    addrs: vec!["127.0.0.1:9999".into()],
                })
                .collect(),
            published_at: 0,
        };
        dht.put(record).await.unwrap();

        // Set up transport selector with our mock.
        let selector = Arc::new(PayloadTransportSelector::new(vec![Box::new(
            MockLocalTransport {
                store: store.clone(),
            },
        )]));

        let source = FallbackShareSource::new(dht, selector);

        // list_candidates should return locators.
        let candidates = source.list_candidates(&mid).await;
        assert_eq!(candidates.len(), params.total_shards);

        // fetch should return a share.
        let share = source.fetch(&candidates[0]).await.unwrap();
        assert!(share.is_some());
        assert_eq!(share.unwrap().slot_index, 0);
    }

    #[tokio::test]
    async fn fallback_source_records_attempts() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(crate::store::LocalShareStore::open(dir.path(), 100).unwrap());

        let params = DissolutionParams::default();
        let (mid, shares) = dissolve(b"attempts test", params).unwrap();
        for s in &shares {
            store.put(s).unwrap();
        }

        let dht = BypassOnionDhtExecutor::new();
        let record = DhtRecord {
            mid_digest: *mid.as_bytes(),
            data_shards: params.data_shards as u8,
            total_shards: params.total_shards as u8,
            version: 1,
            locations: vec![crate::network::types::ShardLocation {
                peer_id_bytes: vec![0; 38],
                shard_index: 0,
                addrs: vec!["127.0.0.1:9999".into()],
            }],
            published_at: 0,
        };
        dht.put(record).await.unwrap();

        /// Transport that fails first.
        struct FailFirst;

        #[async_trait::async_trait]
        impl PayloadTransport for FailFirst {
            fn kind(&self) -> PayloadTransportKind {
                PayloadTransportKind::TcpDirect
            }
            async fn fetch_share(
                &self,
                _: &str,
                _: [u8; 32],
                _: u16,
                _: u32,
            ) -> Result<Option<MiasmaShare>, PayloadTransportError> {
                Err(PayloadTransportError {
                    phase: TransportPhase::Session,
                    message: "simulated TCP failure".into(),
                })
            }
        }

        let selector = Arc::new(PayloadTransportSelector::new(vec![
            Box::new(FailFirst),
            Box::new(MockLocalTransport { store }),
        ]));

        let source = FallbackShareSource::new(dht, selector);
        let candidates = source.list_candidates(&mid).await;
        let share = source.fetch(&candidates[0]).await.unwrap();
        assert!(share.is_some());

        let attempts = source.drain_attempts();
        assert_eq!(attempts.len(), 2);
        assert!(!attempts[0].succeeded); // FailFirst
        assert!(attempts[1].succeeded); // MockLocalTransport
    }
}
