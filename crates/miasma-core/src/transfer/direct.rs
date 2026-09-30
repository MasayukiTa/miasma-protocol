//! Direct receive: the receive engine fed from a WebSocket endpoint instead of
//! the DHT.
//!
//! A receiver behind a network that blocks QUIC and raw TCP cannot run the DHT
//! lookup or fetch pieces through libp2p. With one or more `--via` URLs it needs
//! neither: the record and manifest are read from the endpoint (a sender's
//! daemon behind an outbound tunnel), then every piece, and the ordinary engine
//! ([`run_receive`]) does the rest unchanged — the same piece verification
//! against the manifest, journal, resume, spare-piece retry and progress.

use std::{path::Path, sync::Arc};

use async_trait::async_trait;
use tracing::warn;
use zeroize::Zeroizing;

use super::{
    open_signed_record,
    progress::{Phase, TransferProgress, TransferState},
    receive::{
        resolve_output_target, run_receive, PieceSource, ReceiveOutcome, ReceiveSpec, RetryConfig,
    },
    share_id::{ShareMismatch, TransferId},
    FetchedRecord, SignedRecordError, TransferManifest,
};
use crate::{
    crypto::hash::ContentId,
    network::types::{DhtRecord, ShardLocation},
    share::MiasmaShare,
    transport::ws_direct::{WsClientError, WsDirectClient, MAX_CA_PEM_BYTES, MAX_WS_URL_LEN},
    MiasmaError,
};

/// Most endpoints a receive may be given.
pub const MAX_VIA_ENDPOINTS: usize = 4;

/// Attempts at reading the record before giving up on unreachable endpoints.
const RECORD_ATTEMPTS: u32 = 4;

/// Where a direct receive fetches from.
#[derive(Clone, Default)]
pub struct ViaConfig {
    /// `wss://` or `ws://` endpoints, tried in order.
    pub urls: Vec<String>,
    /// Extra CA certificate(s), PEM text, trusted in addition to the OS store.
    pub ca_pem: Option<String>,
}

impl std::fmt::Debug for ViaConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViaConfig")
            .field("endpoints", &self.urls.len())
            .field("extra_ca", &self.ca_pem.is_some())
            .finish()
    }
}

impl ViaConfig {
    /// `None` when no endpoint is given (the ordinary DHT receive).
    pub fn from_request(urls: Vec<String>, ca_pem: Option<String>) -> Option<Self> {
        let urls: Vec<String> = urls.into_iter().filter(|u| !u.trim().is_empty()).collect();
        if urls.is_empty() {
            None
        } else {
            Some(Self {
                urls: urls.into_iter().map(|u| u.trim().to_owned()).collect(),
                ca_pem: ca_pem.filter(|p| !p.trim().is_empty()),
            })
        }
    }

    /// Check the request's own bounds and build one client per endpoint. Bad
    /// input is refused here, before any connection is made.
    pub fn build_clients(&self) -> Result<Vec<Arc<WsDirectClient>>, MiasmaError> {
        if self.urls.len() > MAX_VIA_ENDPOINTS {
            return Err(MiasmaError::Network(format!(
                "too many --via endpoints (at most {MAX_VIA_ENDPOINTS})"
            )));
        }
        if self.urls.iter().any(|u| u.len() > MAX_WS_URL_LEN)
            || self
                .ca_pem
                .as_ref()
                .is_some_and(|p| p.len() > MAX_CA_PEM_BYTES)
        {
            return Err(MiasmaError::Network(
                "a --via URL or CA file is too large".into(),
            ));
        }
        let ca = self.ca_pem.as_deref().map(str::as_bytes);
        self.urls
            .iter()
            .map(|u| WsDirectClient::new(u, ca).map(Arc::new))
            .collect()
    }
}

/// Pieces from WebSocket endpoints. The holder the engine names (a libp2p peer
/// from the record) is meaningless here and ignored; every endpoint is asked in
/// turn for the piece by `(MID, segment, slot)`.
pub struct WsPieceSource {
    clients: Vec<Arc<WsDirectClient>>,
}

impl WsPieceSource {
    pub fn new(clients: Vec<Arc<WsDirectClient>>) -> Self {
        Self { clients }
    }
}

#[async_trait]
impl PieceSource for WsPieceSource {
    async fn fetch_piece(
        &self,
        mid: &ContentId,
        segment: u32,
        slot: u16,
        _holder: &ShardLocation,
    ) -> Result<Option<MiasmaShare>, MiasmaError> {
        for client in &self.clients {
            match client.fetch_share(*mid.as_bytes(), segment, slot).await {
                Ok(Some(share)) => return Ok(Some(share)),
                Ok(None) => {}
                // The engine retries the segment with backoff; say why once per failure.
                Err(e) => warn!(
                    "piece (segment {segment}, slot {slot}) from {}: {e}",
                    client.display_addr()
                ),
            }
        }
        Ok(None)
    }
}

/// Read and check the record and manifest for `mid` from the endpoints.
///
/// * The first endpoint that has a usable record wins.
/// * Unreachable endpoints are retried with backoff, a few times.
/// * A refused TLS certificate fails at once: retrying cannot change it.
/// * If every reachable endpoint says it has no record, that is the answer.
///
/// This form cannot tell who signed the record: see
/// [`fetch_verified_record_via`].
pub async fn fetch_record_and_manifest_via(
    clients: &[Arc<WsDirectClient>],
    mid: &ContentId,
) -> Result<(DhtRecord, Option<TransferManifest>), MiasmaError> {
    fetch_verified_record_via(clients, mid, None)
        .await
        .map(|f| (f.record, f.manifest))
}

/// As [`fetch_record_and_manifest_via`], over the signed record envelope each
/// endpoint serves, returning the signer.
///
/// With `expected_signer` (from a share ID) an endpoint whose record is signed
/// by any other key is skipped and the next endpoint is asked, so a hostile
/// endpoint listed first cannot decide the result (C-01). If no endpoint has the
/// publisher's record, the error says a record was refused for its signer.
pub async fn fetch_verified_record_via(
    clients: &[Arc<WsDirectClient>],
    mid: &ContentId,
    expected_signer: Option<&[u8; 32]>,
) -> Result<FetchedRecord, MiasmaError> {
    let retry = RetryConfig::default();
    let mut last_transient: Option<WsClientError> = None;

    for attempt in 1..=RECORD_ATTEMPTS {
        let mut all_answered = true;
        let mut refused: Option<MiasmaError> = None;
        for client in clients {
            match client.fetch_record(*mid.as_bytes()).await {
                Ok(Some(envelope)) => {
                    match open_signed_record(mid.as_bytes(), &envelope, expected_signer) {
                        Ok(found) => return Ok(found),
                        Err(e) => {
                            warn!("record from {} refused: {e:?}", client.display_addr());
                            // Keep the first reason; the next endpoint may still be honest.
                            refused.get_or_insert_with(|| record_refusal(e));
                        }
                    }
                }
                Ok(None) => {}
                Err(e) if e.is_permanent() => return Err(e.into()),
                Err(e) => {
                    all_answered = false;
                    last_transient = Some(e);
                }
            }
        }
        if all_answered {
            return Err(refused.unwrap_or_else(|| {
                MiasmaError::Network(
                    "the sender has no record for this ID; check the ID and that the sender's \
                     daemon is running with the file published"
                        .into(),
                )
            }));
        }
        if attempt < RECORD_ATTEMPTS {
            tokio::time::sleep(retry.delay_for(attempt)).await;
        }
    }
    Err(last_transient
        .map(MiasmaError::from)
        .unwrap_or_else(|| MiasmaError::Network("no endpoint could be reached".into())))
}

/// What to tell the person when an endpoint's record was refused.
fn record_refusal(e: SignedRecordError) -> MiasmaError {
    match e {
        SignedRecordError::WrongSigner => MiasmaError::ShareMismatch(ShareMismatch::WrongSigner),
        SignedRecordError::InvalidInner(msg) => MiasmaError::InvalidManifest(msg),
        SignedRecordError::InnerMidMismatch => MiasmaError::InvalidMid(
            "the endpoint answered with a record for a different MID".into(),
        ),
        SignedRecordError::ManifestPublisher => MiasmaError::InvalidManifest(
            "the manifest names a different publisher than the one that signed the record".into(),
        ),
        SignedRecordError::Malformed | SignedRecordError::BadSignature => MiasmaError::Network(
            "the endpoint answered with a record that is not validly signed (is it running the \
             same Miasma version?)"
                .into(),
        ),
    }
}

/// Receive `mid` into `output_path` from the `via` endpoints: the direct
/// counterpart of `MiasmaCoordinator::receive_file`, with the same guarantees
/// (see `transfer::receive`), resume included. Needs no DHT and no libp2p peer.
pub async fn receive_file_via(
    via: &ViaConfig,
    mid: &ContentId,
    output_path: &Path,
    password: Option<Zeroizing<String>>,
    journal_dir: &Path,
    restart: bool,
    progress: Arc<TransferProgress>,
) -> Result<ReceiveOutcome, MiasmaError> {
    receive_file_via_id(
        via,
        &TransferId::Mid(mid.clone()),
        output_path,
        password,
        journal_dir,
        restart,
        progress,
    )
    .await
}

/// As [`receive_file_via`], for what the person typed: a share ID is checked
/// against the record's signer, the manifest's publisher and its protection
/// state before any piece is fetched; a bare MID is accepted unauthenticated.
/// `output_path` may be an existing folder (see
/// `MiasmaCoordinator::receive_file_id`).
pub async fn receive_file_via_id(
    via: &ViaConfig,
    target: &TransferId,
    output_path: &Path,
    password: Option<Zeroizing<String>>,
    journal_dir: &Path,
    restart: bool,
    progress: Arc<TransferProgress>,
) -> Result<ReceiveOutcome, MiasmaError> {
    progress.set_phase(Phase::Preparing);
    let fail = |e: MiasmaError| {
        progress.set_state(TransferState::Failed, Some(e.to_string()), false);
        e
    };
    let mid = target.mid();
    let expect = target.share_id().copied();
    if let Some(id) = &expect {
        progress.set_share_id(Some(id.to_string()));
        progress.set_share_id_checked(true);
    }
    let clients = via.build_clients().map_err(fail)?;
    let fetched = fetch_verified_record_via(&clients, &mid, expect.as_ref().map(|s| s.publisher()))
        .await
        .map_err(fail)?;
    let output = resolve_output_target(output_path, fetched.manifest.as_ref()).map_err(fail)?;
    if output != output_path {
        progress.set_name(output.to_string_lossy());
    }
    let source = WsPieceSource::new(clients);
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
