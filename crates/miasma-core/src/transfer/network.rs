//! Wiring the receive engine to the real network.
//!
//! [`TransportPieceSource`] adapts the existing payload transport selector to
//! [`PieceSource`]; [`MiasmaCoordinator::receive_file`] reads the record and its
//! manifest from the DHT **once** and hands them to the engine. (The older
//! streaming path asks the DHT for the whole record again for every segment.)

use std::{path::Path, sync::Arc};

use async_trait::async_trait;
use zeroize::Zeroizing;

use super::{
    progress::{Phase, TransferProgress},
    receive::{run_receive, PieceSource, ReceiveOutcome, ReceiveSpec, RetryConfig},
    TransferManifest,
};
use crate::{
    crypto::hash::ContentId,
    network::{
        types::{DhtRecord, ShardLocation},
        MiasmaCoordinator,
    },
    share::MiasmaShare,
    transport::payload::PayloadTransportSelector,
    MiasmaError,
};

/// The real network as a [`PieceSource`].
pub struct TransportPieceSource {
    selector: Arc<PayloadTransportSelector>,
}

impl TransportPieceSource {
    pub fn new(selector: Arc<PayloadTransportSelector>) -> Self {
        Self { selector }
    }
}

#[async_trait]
impl PieceSource for TransportPieceSource {
    async fn fetch_piece(
        &self,
        mid: &ContentId,
        segment: u32,
        slot: u16,
        holder: &ShardLocation,
    ) -> Result<Option<MiasmaShare>, MiasmaError> {
        // Same convention as `FallbackShareSource`: the first announced address.
        let addr = holder.addrs.first().map(String::as_str).unwrap_or("");
        match self
            .selector
            .fetch_share(addr, *mid.as_bytes(), slot, segment)
            .await
        {
            Ok(fetched) => Ok(Some(fetched.share)),
            // Every transport failed for this holder; the engine tries the next.
            Err(_) => Ok(None),
        }
    }
}

/// Attempts to find the record before giving up: a publisher's record can take
/// a moment to become visible to a fresh node.
const RECORD_LOOKUP_ATTEMPTS: u32 = 6;

/// How long a receive waits for the link to its configured bootstrap peers
/// before it gives up with "not connected". Longer than the redial backoff cap
/// (30 s) so at least one backed-off redial fits inside it.
const PEER_CONNECT_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

impl MiasmaCoordinator {
    /// The production [`PieceSource`]: fetches pieces through this node's
    /// payload transports. Public so a latency/throughput probe can time single
    /// fetches without going through a whole transfer.
    pub fn piece_source(&self) -> TransportPieceSource {
        TransportPieceSource::new(self.transport_selector())
    }

    /// Read the record and manifest for `mid` from the DHT, retrying with backoff.
    ///
    /// Every attempt first makes sure the node has a link to the network (see
    /// `DhtHandle::ensure_connected`): a lookup on an empty routing table answers
    /// "not found" at once, so without the wait the attempts are spent before the
    /// link to the sender is back and the receive fails with `no record found`
    /// although the record exists. If the configured bootstrap peers stay
    /// unreachable, one last lookup is still made (the record may be held locally)
    /// and then the error names the unreachable bootstrap addresses.
    pub async fn fetch_record_and_manifest(
        &self,
        mid: &ContentId,
    ) -> Result<(DhtRecord, Option<TransferManifest>), MiasmaError> {
        let retry = RetryConfig::default();
        for attempt in 1..=RECORD_LOOKUP_ATTEMPTS {
            let link = self.dht_handle().ensure_connected(PEER_CONNECT_WAIT).await;
            if let Some(found) = self
                .dht_handle()
                .get_record_with_manifest(*mid.as_bytes())
                .await?
            {
                return Ok(found);
            }
            // Unreachable after the full wait: more lookups cannot succeed.
            link?;
            if attempt < RECORD_LOOKUP_ATTEMPTS {
                tokio::time::sleep(retry.delay_for(attempt)).await;
            }
        }
        Err(MiasmaError::Dht(format!(
            "no record found for {} after {RECORD_LOOKUP_ATTEMPTS} attempts",
            mid.to_string()
        )))
    }

    /// Receive `mid` into `output_path`: verified piece by piece, resumable, with
    /// `progress` kept current. See `transfer::receive` for the guarantees.
    ///
    /// Running this again with the same arguments after it returned
    /// `Paused` or `Cancelled` (or after the process died) resumes it.
    pub async fn receive_file(
        &self,
        mid: &ContentId,
        output_path: &Path,
        password: Option<Zeroizing<String>>,
        journal_dir: &Path,
        restart: bool,
        progress: Arc<TransferProgress>,
    ) -> Result<ReceiveOutcome, MiasmaError> {
        progress.set_phase(Phase::Preparing);
        let (record, manifest) = match self.fetch_record_and_manifest(mid).await {
            Ok(found) => found,
            Err(e) => {
                progress.set_state(
                    super::progress::TransferState::Failed,
                    Some(e.to_string()),
                    false,
                );
                return Err(e);
            }
        };
        let source = self.piece_source();
        run_receive(
            &source,
            ReceiveSpec {
                mid: mid.clone(),
                record,
                manifest,
                password,
                output_path: output_path.to_path_buf(),
                journal_dir: journal_dir.to_path_buf(),
                restart,
                retry: RetryConfig::default(),
            },
            progress,
        )
        .await
    }
}
