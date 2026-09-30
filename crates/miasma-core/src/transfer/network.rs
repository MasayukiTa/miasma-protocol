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
    progress::{Phase, TransferProgress, TransferState},
    receive::{
        resolve_output_target, run_receive, PieceSource, ReceiveOutcome, ReceiveSpec, RetryConfig,
    },
    share_id::TransferId,
    FetchedRecord, TransferManifest,
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
        self.fetch_verified_record(mid, None)
            .await
            .map(|f| (f.record, f.manifest))
    }

    /// As [`fetch_record_and_manifest`](Self::fetch_record_and_manifest), also
    /// returning the record's signer. With `expected_signer` (from a share ID)
    /// only a record signed by exactly that key is accepted: answers from other
    /// signers are ignored while the lookup keeps waiting for the publisher's
    /// own (C-01), and the error says so if none arrives.
    pub async fn fetch_verified_record(
        &self,
        mid: &ContentId,
        expected_signer: Option<[u8; 32]>,
    ) -> Result<FetchedRecord, MiasmaError> {
        let retry = RetryConfig::default();
        for attempt in 1..=RECORD_LOOKUP_ATTEMPTS {
            let link = self.dht_handle().ensure_connected(PEER_CONNECT_WAIT).await;
            if let Some(found) = self
                .dht_handle()
                .get_signed_record(*mid.as_bytes(), expected_signer)
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
        Err(MiasmaError::Dht(match expected_signer {
            Some(_) => format!(
                "no record signed by the publisher named in the share ID was found for {} after \
                 {RECORD_LOOKUP_ATTEMPTS} attempts (records from any other signer are ignored)",
                mid.to_string()
            ),
            None => format!(
                "no record found for {} after {RECORD_LOOKUP_ATTEMPTS} attempts",
                mid.to_string()
            ),
        }))
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
        self.receive_file_id(
            &TransferId::Mid(mid.clone()),
            output_path,
            password,
            journal_dir,
            restart,
            progress,
        )
        .await
    }

    /// As [`receive_file`](Self::receive_file), for what the person typed: a
    /// share ID (the record must be signed by its publisher, and the manifest's
    /// publisher, protection state and MID must agree with it, all before any
    /// piece is fetched), or a bare MID (accepted, `publisher_authenticated`
    /// stays false).
    ///
    /// `output_path` may be an existing folder: the file is then written inside
    /// it under the name the manifest carries, never over an existing file.
    pub async fn receive_file_id(
        &self,
        target: &TransferId,
        output_path: &Path,
        password: Option<Zeroizing<String>>,
        journal_dir: &Path,
        restart: bool,
        progress: Arc<TransferProgress>,
    ) -> Result<ReceiveOutcome, MiasmaError> {
        progress.set_phase(Phase::Preparing);
        let mid = target.mid();
        let expect = target.share_id().copied();
        if let Some(id) = &expect {
            progress.set_share_id(Some(id.to_string()));
            progress.set_share_id_checked(true);
        }
        let fail = |e: MiasmaError| {
            progress.set_state(TransferState::Failed, Some(e.to_string()), false);
            e
        };
        let fetched = self
            .fetch_verified_record(&mid, expect.as_ref().map(|s| *s.publisher()))
            .await
            .map_err(fail)?;
        let output = resolve_output_target(output_path, fetched.manifest.as_ref()).map_err(fail)?;
        if output != output_path {
            progress.set_name(output.to_string_lossy());
        }
        let source = self.piece_source();
        run_receive(
            &source,
            ReceiveSpec {
                mid,
                record: fetched.record,
                manifest: fetched.manifest,
                password,
                output_path: output,
                journal_dir: journal_dir.to_path_buf(),
                restart,
                retry: RetryConfig::default(),
                expect,
                record_signer: Some(fetched.signer),
            },
            progress,
        )
        .await
    }
}
