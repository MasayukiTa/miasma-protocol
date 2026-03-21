/// Miasma libp2p node — Phase 4b live-wired anonymous trust and descriptor routing.
///
/// Transport: TCP + QUIC for local loopback testing and production paths
/// DHT: Kademlia via `DhtHandle` / `OnionAwareDhtExecutor` (ADR-002)
/// Share exchange: `/miasma/share/1.0.0` request-response protocol
/// Admission: `/miasma/admission/1.0.0` PoW proof exchange (ADR-004)
/// Credential: `/miasma/credential/1.0.0` credential exchange (ADR-005)
/// Descriptor: `/miasma/descriptor/1.0.0` descriptor exchange (ADR-005)
/// NAT: AutoNAT + DCUtR + relay
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt as _;
use libp2p::{
    autonat, dcutr, identify,
    identity::Keypair,
    kad::{self, store::MemoryStore, store::RecordStore},
    noise, ping, relay, request_response, yamux,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol, Swarm,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::{crypto::keyderive::NodeKeys, share::MiasmaShare, store::LocalShareStore, MiasmaError};

use super::admission_policy::{AdmissionSignals, HybridAdmissionPolicy};
use super::bbs_credential::{
    BbsCredential, BbsCredentialAttributes, BbsCredentialWallet, BbsIssuer, BbsIssuerKey,
    BbsIssuerRegistry, DisclosurePolicy, bbs_create_proof, bbs_verify_proof,
};
use super::credential::{
    self, CredentialIssuer, CredentialPresentation, CredentialStats, CredentialTier,
    CredentialWallet, IssuerRegistry, SignedCredential, CAP_ROUTE, CAP_STORE,
};
use super::descriptor::{
    DescriptorStats, DescriptorStore, PeerCapabilities, PeerDescriptor, ReachabilityKind,
    ResourceProfile,
};
use super::onion_relay::{
    OnionRelayCodec, OnionRelayRequest, OnionRelayResponse,
};
use super::path_selection::PathSelectionStats;
use super::peer_state::{AdmissionStats, PeerRegistry, RejectionReason};
use super::routing::{self, RoutingStats, RoutingTable};
use super::sybil::{self, NodeIdPoW, SignedDhtRecord};
use super::types::{DhtRecord, NodeType};

// ─── Share-exchange wire types ────────────────────────────────────────────────

/// Request a specific shard from a remote peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareFetchRequest {
    pub mid_digest: [u8; 32],
    pub slot_index: u16,
    pub segment_index: u32,
}

/// Response to a `ShareFetchRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareFetchResponse {
    /// The requested shard, or `None` if not stored on this peer.
    pub share: Option<MiasmaShare>,
}

// ─── Admission wire types (ADR-004 Phase 3b) ────────────────────────────────

/// PoW admission request — sent after Identify to exchange proof of work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionRequest {
    /// The requesting node's own PoW proof.
    pub pow: NodeIdPoW,
}

/// PoW admission response — peer replies with their own PoW proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionResponse {
    /// The responding node's PoW proof.
    pub pow: NodeIdPoW,
}

// ─── Credential exchange wire types (ADR-005 Phase 4b) ──────────────────────

/// Request a credential from an issuer peer after admission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// Holder's ephemeral public key (for the current epoch).
    pub ephemeral_pubkey: [u8; 32],
    /// Holder's holder_tag (BLAKE3 of ephemeral pubkey).
    pub holder_tag: [u8; 32],
    /// Epoch for which the credential is requested.
    pub epoch: u64,
    /// BBS+ link secret (needed for BBS+ credential issuance).
    /// The issuer embeds this in the BBS+ credential so the holder can prove possession.
    #[serde(default)]
    pub bbs_link_secret: Option<[u8; 32]>,
}

/// Credential exchange response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
    /// The signed credential (Ed25519), or None if the peer is not eligible.
    pub credential: Option<SignedCredential>,
    /// BBS+ credential (privacy-preserving, within-epoch unlinkable).
    #[serde(default)]
    pub bbs_credential: Option<BbsCredential>,
}

// ─── Descriptor exchange wire types (ADR-005 Phase 4b) ──────────────────────

/// Request a peer's descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorRequest {
    /// Requester's own descriptor (reciprocal exchange).
    pub descriptor: Option<PeerDescriptor>,
}

/// Descriptor exchange response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorResponse {
    /// The peer's current descriptor.
    pub descriptor: Option<PeerDescriptor>,
}

// ─── CredentialCodec ────────────────────────────────────────────────────────

/// Max message size for credential exchange (8 KiB).
const CREDENTIAL_MSG_MAX: usize = 8 * 1024;

/// Bincode + 4-byte LE length-prefix codec for `/miasma/credential/1.0.0`.
#[derive(Clone, Default)]
pub struct CredentialCodec;

#[async_trait::async_trait]
impl request_response::Codec for CredentialCodec {
    type Protocol = StreamProtocol;
    type Request = CredentialRequest;
    type Response = CredentialResponse;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> std::io::Result<Self::Request>
    where T: futures::AsyncRead + Unpin + Send {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > CREDENTIAL_MSG_MAX {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "credential msg too large"));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> std::io::Result<Self::Response>
    where T: futures::AsyncRead + Unpin + Send {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > CREDENTIAL_MSG_MAX {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "credential msg too large"));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
    async fn write_request<T>(&mut self, _: &StreamProtocol, io: &mut T, req: Self::Request) -> std::io::Result<()>
    where T: futures::AsyncWrite + Unpin + Send {
        use futures::AsyncWriteExt;
        let buf = bincode::serialize(&req).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        io.write_all(&(buf.len() as u32).to_le_bytes()).await?;
        io.write_all(&buf).await
    }
    async fn write_response<T>(&mut self, _: &StreamProtocol, io: &mut T, res: Self::Response) -> std::io::Result<()>
    where T: futures::AsyncWrite + Unpin + Send {
        use futures::AsyncWriteExt;
        let buf = bincode::serialize(&res).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        io.write_all(&(buf.len() as u32).to_le_bytes()).await?;
        io.write_all(&buf).await
    }
}

// ─── DescriptorCodec ────────────────────────────────────────────────────────

/// Max message size for descriptor exchange (16 KiB).
const DESCRIPTOR_MSG_MAX: usize = 16 * 1024;

/// Bincode + 4-byte LE length-prefix codec for `/miasma/descriptor/1.0.0`.
#[derive(Clone, Default)]
pub struct DescriptorCodec;

#[async_trait::async_trait]
impl request_response::Codec for DescriptorCodec {
    type Protocol = StreamProtocol;
    type Request = DescriptorRequest;
    type Response = DescriptorResponse;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> std::io::Result<Self::Request>
    where T: futures::AsyncRead + Unpin + Send {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > DESCRIPTOR_MSG_MAX {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "descriptor msg too large"));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> std::io::Result<Self::Response>
    where T: futures::AsyncRead + Unpin + Send {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > DESCRIPTOR_MSG_MAX {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "descriptor msg too large"));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
    async fn write_request<T>(&mut self, _: &StreamProtocol, io: &mut T, req: Self::Request) -> std::io::Result<()>
    where T: futures::AsyncWrite + Unpin + Send {
        use futures::AsyncWriteExt;
        let buf = bincode::serialize(&req).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        io.write_all(&(buf.len() as u32).to_le_bytes()).await?;
        io.write_all(&buf).await
    }
    async fn write_response<T>(&mut self, _: &StreamProtocol, io: &mut T, res: Self::Response) -> std::io::Result<()>
    where T: futures::AsyncWrite + Unpin + Send {
        use futures::AsyncWriteExt;
        let buf = bincode::serialize(&res).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        io.write_all(&(buf.len() as u32).to_le_bytes()).await?;
        io.write_all(&buf).await
    }
}

// ─── ShareCodec ───────────────────────────────────────────────────────────────

/// Bincode + 4-byte LE length-prefix codec for `/miasma/share/1.0.0`.
#[derive(Clone, Default)]
pub struct ShareCodec;

/// Max message size for share exchange (4 MiB).
const SHARE_MSG_MAX: usize = 4 * 1024 * 1024;
/// Max message size for admission protocol (4 KiB — PoW proofs are tiny).
const ADMISSION_MSG_MAX: usize = 4 * 1024;

#[async_trait::async_trait]
impl request_response::Codec for ShareCodec {
    type Protocol = StreamProtocol;
    type Request = ShareFetchRequest;
    type Response = ShareFetchResponse;

    async fn read_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > SHARE_MSG_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("share exchange message too large: {len} bytes"),
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > SHARE_MSG_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("share exchange message too large: {len} bytes"),
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
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
        io.write_all(&buf).await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
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
        io.write_all(&buf).await?;
        Ok(())
    }
}

// ─── AdmissionCodec ──────────────────────────────────────────────────────────

/// Bincode + 4-byte LE length-prefix codec for `/miasma/admission/1.0.0`.
#[derive(Clone, Default)]
pub struct AdmissionCodec;

#[async_trait::async_trait]
impl request_response::Codec for AdmissionCodec {
    type Protocol = StreamProtocol;
    type Request = AdmissionRequest;
    type Response = AdmissionResponse;

    async fn read_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > ADMISSION_MSG_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("admission message too large: {len} bytes"),
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > ADMISSION_MSG_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("admission message too large: {len} bytes"),
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        bincode::deserialize(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
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
        io.write_all(&buf).await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
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
        io.write_all(&buf).await?;
        Ok(())
    }
}

// ─── DHT command channel ──────────────────────────────────────────────────────

pub enum DhtCommand {
    /// PUT a serialised record into Kademlia.
    Put {
        key: Vec<u8>,
        value: Vec<u8>,
        reply: oneshot::Sender<Result<(), MiasmaError>>,
    },
    /// GET raw record bytes from Kademlia.
    Get {
        key: Vec<u8>,
        reply: oneshot::Sender<Result<Option<Vec<u8>>, MiasmaError>>,
    },
    /// Register a bootstrap peer and dial from within the running event loop.
    ///
    /// Dialing from inside the event loop avoids the ECONNREFUSED race that
    /// occurs when `swarm.dial()` is called before the remote node's `run()`
    /// has started accepting connections.
    AddBootstrapPeer {
        peer_id: PeerId,
        addr: Multiaddr,
        reply: oneshot::Sender<()>,
    },
    /// Trigger Kademlia FIND_NODE bootstrap for this node's own key.
    BootstrapDht {
        reply: oneshot::Sender<Result<(), MiasmaError>>,
    },
    /// Query the number of currently connected peers.
    GetPeerCount {
        reply: oneshot::Sender<usize>,
    },
    /// Query admission statistics.
    GetAdmissionStats {
        reply: oneshot::Sender<AdmissionStats>,
    },
    /// Query routing overlay statistics.
    GetRoutingStats {
        reply: oneshot::Sender<RoutingStats>,
    },
    /// Query credential subsystem statistics.
    GetCredentialStats {
        reply: oneshot::Sender<CredentialStats>,
    },
    /// Query descriptor store statistics.
    GetDescriptorStats {
        reply: oneshot::Sender<DescriptorStats>,
    },
    /// Query path selection statistics.
    GetPathSelectionStats {
        reply: oneshot::Sender<PathSelectionStats>,
    },
    /// Query Freenet-style outcome metrics.
    GetOutcomeMetrics {
        reply: oneshot::Sender<super::metrics::OutcomeMetrics>,
    },
    /// Query relay peer info for coordinator relay routing.
    /// Returns `(PeerId, addresses)` for relay-capable peers with known PeerId.
    GetRelayPeers {
        reply: oneshot::Sender<Vec<(PeerId, Vec<String>)>>,
    },
    /// Query relay peers with onion X25519 public keys for onion-encrypted retrieval.
    GetRelayOnionInfo {
        reply: oneshot::Sender<Vec<crate::onion::circuit::RelayInfo>>,
    },
    /// Send an onion relay request to a specific peer.
    /// Used by the coordinator to initiate onion-encrypted share fetches.
    SendOnionRequest {
        peer_id: PeerId,
        addrs: Vec<String>,
        request: OnionRelayRequest,
        /// Return key that the relay should use to encrypt the response.
        /// Stored so the node can match the outbound request to the key.
        return_key: [u8; 32],
        reply: oneshot::Sender<Result<OnionRelayResponse, MiasmaError>>,
    },
    /// Query this node's onion static public key.
    GetOnionPubkey {
        reply: oneshot::Sender<[u8; 32]>,
    },
    /// Query this node's current NAT reachability status.
    GetNatStatus {
        reply: oneshot::Sender<bool>,
    },
}

/// Sender side of the DHT command channel.
///
/// Wraps the low-level channel with typed `put`/`get_record` helpers that
/// handle bincode serialisation / deserialisation of `DhtRecord`.
#[derive(Clone)]
pub struct DhtHandle {
    pub(crate) tx: mpsc::Sender<DhtCommand>,
}

impl DhtHandle {
    /// Publish a `DhtRecord` to Kademlia.
    pub async fn put(&self, record: DhtRecord) -> Result<(), MiasmaError> {
        let key = record.mid_digest.to_vec();
        let value = bincode::serialize(&record)
            .map_err(|e| MiasmaError::Serialization(e.to_string()))?;
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::Put { key, value, reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await
            .map_err(|_| MiasmaError::Network("DHT reply channel dropped".into()))?
    }

    /// Register a bootstrap peer inside the running event loop.
    ///
    /// Sends `AddBootstrapPeer` to the event loop so the dial happens from
    /// within `run()`, ensuring the remote TCP socket is already accepting.
    pub async fn add_bootstrap_peer(
        &self,
        peer_id: PeerId,
        addr: Multiaddr,
    ) -> Result<(), MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::AddBootstrapPeer { peer_id, addr, reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))
    }

    /// Trigger Kademlia FIND_NODE bootstrap.
    ///
    /// Call after `add_bootstrap_peer`; allow ~1–3 s for convergence before
    /// issuing DHT PUT or GET operations.
    pub async fn bootstrap(&self) -> Result<(), MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::BootstrapDht { reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))?
    }

    /// Return the number of currently connected peers.
    pub async fn peer_count(&self) -> Result<usize, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::GetPeerCount { reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))
    }

    /// Retrieve a `DhtRecord` from Kademlia by raw mid-digest bytes.
    pub async fn get_record(
        &self,
        mid_digest: [u8; 32],
    ) -> Result<Option<DhtRecord>, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::Get { key: mid_digest.to_vec(), reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        let raw_opt = rx
            .await
            .map_err(|_| MiasmaError::Network("DHT reply channel dropped".into()))??;
        match raw_opt {
            Some(bytes) => {
                // Try to unwrap SignedDhtRecord envelope first, fall back to plain DhtRecord.
                if let Ok(signed) = bincode::deserialize::<SignedDhtRecord>(&bytes) {
                    if signed.verify_signature() {
                        return Ok(Some(
                            bincode::deserialize(&signed.value)
                                .map_err(|e| MiasmaError::Serialization(e.to_string()))?,
                        ));
                    } else {
                        warn!("DHT GET: record has invalid signature, rejecting");
                        return Ok(None);
                    }
                }
                // Fall back: plain DhtRecord (transition compatibility).
                Ok(Some(
                    bincode::deserialize(&bytes)
                        .map_err(|e| MiasmaError::Serialization(e.to_string()))?,
                ))
            }
            None => Ok(None),
        }
    }

    /// Query admission statistics from the node.
    pub async fn admission_stats(&self) -> Result<AdmissionStats, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::GetAdmissionStats { reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))
    }

    /// Query routing overlay statistics from the node.
    pub async fn routing_stats(&self) -> Result<RoutingStats, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::GetRoutingStats { reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))
    }

    /// Query credential subsystem statistics.
    pub async fn credential_stats(&self) -> Result<CredentialStats, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::GetCredentialStats { reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))
    }

    /// Query descriptor store statistics.
    pub async fn descriptor_stats(&self) -> Result<DescriptorStats, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::GetDescriptorStats { reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))
    }

    /// Query path selection statistics.
    pub async fn path_selection_stats(&self) -> Result<PathSelectionStats, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::GetPathSelectionStats { reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))
    }

    /// Query Freenet-style outcome metrics.
    pub async fn outcome_metrics(&self) -> Result<super::metrics::OutcomeMetrics, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::GetOutcomeMetrics { reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))
    }

    /// Query relay peer info for relay circuit address construction.
    ///
    /// Returns `(PeerId, addresses)` for each relay-capable descriptor with a
    /// known PeerId mapping. The coordinator uses this to build libp2p relay
    /// circuit addresses for anonymity-backed retrieval.
    pub async fn relay_peers(&self) -> Result<Vec<(PeerId, Vec<String>)>, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::GetRelayPeers { reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))
    }

    /// Query relay peers with onion X25519 public keys.
    pub async fn relay_onion_info(&self) -> Result<Vec<crate::onion::circuit::RelayInfo>, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::GetRelayOnionInfo { reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))
    }

    /// Send an onion relay request to a peer and await the response.
    pub async fn send_onion_request(
        &self,
        peer_id: PeerId,
        addrs: Vec<String>,
        request: OnionRelayRequest,
        return_key: [u8; 32],
    ) -> Result<OnionRelayResponse, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::SendOnionRequest { peer_id, addrs, request, return_key, reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await
            .map_err(|_| MiasmaError::Network("onion relay reply dropped".into()))?
    }

    /// Query this node's onion X25519 static public key.
    pub async fn onion_pubkey(&self) -> Result<[u8; 32], MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::GetOnionPubkey { reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))
    }

    /// Query whether this node is publicly reachable (AutoNAT).
    pub async fn nat_publicly_reachable(&self) -> Result<bool, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(DhtCommand::GetNatStatus { reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("DHT command channel closed".into()))?;
        rx.await.map_err(|_| MiasmaError::Network("DHT reply dropped".into()))
    }
}

// ─── Share-exchange command channel ──────────────────────────────────────────

pub struct ShareCommand {
    pub peer_id: PeerId,
    /// Known multiaddr strings for the peer (used to dial before sending).
    pub addrs: Vec<String>,
    pub request: ShareFetchRequest,
    pub reply: oneshot::Sender<Result<Option<MiasmaShare>, MiasmaError>>,
}

/// Sender side of the share-exchange command channel.
#[derive(Clone)]
pub struct ShareExchangeHandle {
    pub(crate) tx: mpsc::Sender<ShareCommand>,
}

impl ShareExchangeHandle {
    /// Fetch a shard from a specific peer.
    pub async fn fetch(
        &self,
        peer_id: PeerId,
        addrs: Vec<String>,
        request: ShareFetchRequest,
    ) -> Result<Option<MiasmaShare>, MiasmaError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ShareCommand { peer_id, addrs, request, reply: tx })
            .await
            .map_err(|_| MiasmaError::Network("share exchange channel closed".into()))?;
        rx.await
            .map_err(|_| MiasmaError::Network("share exchange reply dropped".into()))?
    }
}

// ─── Behaviour ────────────────────────────────────────────────────────────────

/// Combined libp2p behaviour for a Miasma node.
#[derive(NetworkBehaviour)]
pub struct MiasmaBehaviour {
    pub(crate) kademlia: kad::Behaviour<MemoryStore>,
    pub(crate) identify: identify::Behaviour,
    pub(crate) ping: ping::Behaviour,
    pub(crate) autonat: autonat::Behaviour,
    pub(crate) relay: relay::client::Behaviour,
    pub(crate) dcutr: dcutr::Behaviour,
    /// Share fetch: `/miasma/share/1.0.0` request-response.
    pub(crate) share_exchange: request_response::Behaviour<ShareCodec>,
    /// PoW admission: `/miasma/admission/1.0.0` request-response.
    pub(crate) admission: request_response::Behaviour<AdmissionCodec>,
    /// Credential exchange: `/miasma/credential/1.0.0` request-response.
    pub(crate) credential_exchange: request_response::Behaviour<CredentialCodec>,
    /// Descriptor exchange: `/miasma/descriptor/1.0.0` request-response.
    pub(crate) descriptor_exchange: request_response::Behaviour<DescriptorCodec>,
    /// Onion relay: `/miasma/onion/1.0.0` request-response.
    pub(crate) onion_relay: request_response::Behaviour<OnionRelayCodec>,
}

// ─── MiasmaNode ───────────────────────────────────────────────────────────────

pub struct MiasmaNode {
    pub local_peer_id: PeerId,
    pub node_type: NodeType,
    swarm: Swarm<MiasmaBehaviour>,
    shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: mpsc::Receiver<()>,
    // DHT command channel (rx side owned by this node).
    dht_tx: mpsc::Sender<DhtCommand>,
    dht_rx: mpsc::Receiver<DhtCommand>,
    // Share exchange command channel.
    share_tx: mpsc::Sender<ShareCommand>,
    share_rx: mpsc::Receiver<ShareCommand>,
    // Pending Kademlia queries awaiting resolution.
    pending_puts: HashMap<kad::QueryId, oneshot::Sender<Result<(), MiasmaError>>>,
    pending_gets: HashMap<
        kad::QueryId,
        (oneshot::Sender<Result<Option<Vec<u8>>, MiasmaError>>, Option<Vec<u8>>),
    >,
    // Pending outbound share-fetch requests.
    pending_share_fetches:
        HashMap<request_response::OutboundRequestId, oneshot::Sender<Result<Option<MiasmaShare>, MiasmaError>>>,
    // Pending outbound admission requests: req_id → peer_id.
    pending_admissions: HashMap<request_response::OutboundRequestId, PeerId>,
    /// Local share store — used to serve inbound `ShareFetchRequest`s.
    local_store: Option<Arc<LocalShareStore>>,
    /// Optional channel to notify when a Kademlia PUT is acknowledged by remote peers.
    replication_success_tx: Option<mpsc::Sender<[u8; 32]>>,
    /// Optional channel to emit topology change events (peer connect/disconnect).
    topology_tx: Option<mpsc::Sender<super::types::TopologyEvent>>,
    /// When true, skip address filtering and PoW checks (loopback/private allowed).
    allow_local_addresses: bool,
    /// This node's pre-mined PoW proof for admission exchanges.
    local_pow: NodeIdPoW,
    /// Per-peer trust state tracking.
    peer_registry: PeerRegistry,
    /// Ed25519 signing key for signing DHT records.
    dht_signing_key: ed25519_dalek::SigningKey,
    /// Addresses held per peer while awaiting admission verification.
    /// Once verified, these are promoted to Kademlia.
    pending_peer_addrs: HashMap<PeerId, Vec<Multiaddr>>,
    /// Routing overlay: trust preference, IP diversity, reliability tracking.
    routing_table: RoutingTable,
    /// Tick counter for periodic network-size observation (difficulty adjustment).
    event_tick: u64,

    // ── Phase 4b: anonymous trust, descriptors, hybrid admission ────────
    /// This node's Ed25519 credential issuer (signs credentials for admitted peers).
    credential_issuer: CredentialIssuer,
    /// This node's BBS+ credential issuer (privacy-preserving credentials).
    bbs_issuer: BbsIssuer,
    /// BBS+ issuer key (needed for key bytes in credential).
    bbs_issuer_key: BbsIssuerKey,
    /// BBS+ credential wallet (stores BBS+ credentials from other issuers).
    bbs_wallet: BbsCredentialWallet,
    /// Registry of known BBS+ issuer public keys.
    bbs_issuer_registry: BbsIssuerRegistry,
    /// This node's credential wallet (holds credentials from other issuers).
    credential_wallet: CredentialWallet,
    /// Registry of known credential issuers (bootstrap: all verified = issuers).
    issuer_registry: IssuerRegistry,
    /// Peer descriptor store (structured routing material).
    descriptor_store: DescriptorStore,
    /// Hybrid admission policy (PoW + diversity + reachability + credential).
    admission_policy: HybridAdmissionPolicy,
    /// This node's own resource profile.
    resource_profile: ResourceProfile,
    /// Pending credential requests: req_id → peer_id.
    pending_credential_reqs: HashMap<request_response::OutboundRequestId, PeerId>,
    /// Pending descriptor requests: req_id → peer_id.
    pending_descriptor_reqs: HashMap<request_response::OutboundRequestId, PeerId>,
    /// Current AutoNAT status: true if publicly reachable (can relay for others).
    nat_publicly_reachable: bool,
    /// This node's X25519 static key for onion layer encryption/decryption.
    onion_static_secret: [u8; 32],
    /// X25519 public key derived from onion_static_secret (published in descriptors).
    onion_static_pubkey: [u8; 32],
    /// Pending onion relay requests: req_id → relay return key (for response encryption).
    pending_onion_relays: HashMap<request_response::OutboundRequestId, [u8; 32]>,
    /// Pending onion relay reply channels: req_id → reply sender.
    pending_onion_replies: HashMap<request_response::OutboundRequestId, oneshot::Sender<Result<OnionRelayResponse, MiasmaError>>>,
    /// Inbound onion relay response channels: req_id → inbound channel.
    /// When we're a relay and make a sub-request (R1→R2 or R2→Target),
    /// we store the inbound channel here so we can relay the response back.
    pending_onion_inbound_channels: HashMap<
        request_response::OutboundRequestId,
        request_response::ResponseChannel<OnionRelayResponse>,
    >,
}

impl MiasmaNode {
    /// Build a node from the given master key.
    pub fn new(
        master_key: &[u8; 32],
        node_type: NodeType,
        listen_addr: &str,
    ) -> Result<Self, MiasmaError> {
        let node_keys = NodeKeys::derive(master_key)?;

        let mut signing_bytes: [u8; 32] = *node_keys.dht_signing_key;
        let keypair = Keypair::ed25519_from_bytes(&mut signing_bytes)
            .map_err(|e| MiasmaError::KeyDerivation(e.to_string()))?;

        // Derive Ed25519 signing key for DHT record signing.
        let dht_signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_bytes);
        zeroize::Zeroize::zeroize(&mut signing_bytes);

        let local_peer_id = PeerId::from(keypair.public());
        info!("Miasma node: peer_id={local_peer_id}, type={node_type:?}");

        // Mine PoW proof for this node's identity.
        // At difficulty 8 this is ~256 BLAKE3 hashes — sub-millisecond.
        let pubkey_bytes = dht_signing_key.verifying_key().to_bytes();
        let local_pow = sybil::mine_pow(pubkey_bytes, sybil::DEFAULT_POW_DIFFICULTY);
        debug!("PoW mined: nonce={}, difficulty={}", local_pow.nonce, sybil::DEFAULT_POW_DIFFICULTY);

        let swarm = build_swarm(keypair, local_peer_id, listen_addr)?;

        // Auto-detect local mode: if listening on loopback, allow local addresses
        // through the Identify filter so loopback-based tests and local development work.
        let allow_local = listen_addr.contains("127.0.0.1") || listen_addr.contains("::1");

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let (dht_tx, dht_rx) = mpsc::channel(64);
        let (share_tx, share_rx) = mpsc::channel(64);

        // Derive credential issuer key from DHT signing key (deterministic).
        let cred_issuer_key = ed25519_dalek::SigningKey::from_bytes(
            blake3::hash(&[b"miasma-cred-issuer-v1".as_slice(), dht_signing_key.as_bytes()].concat())
                .as_bytes(),
        );
        let credential_issuer = CredentialIssuer::new(cred_issuer_key);

        // Derive BBS+ issuer key from the same DHT signing key (deterministic).
        let bbs_seed = blake3::hash(
            &[b"miasma-bbs-issuer-v1".as_slice(), dht_signing_key.as_bytes()].concat(),
        );
        let bbs_issuer_key = BbsIssuerKey::from_seed(bbs_seed.as_bytes());
        let bbs_issuer = BbsIssuer::new(bbs_issuer_key.clone());

        // Derive X25519 onion static key from the DHT signing key.
        let onion_static_secret = {
            let derived = crate::onion::packet::derive_onion_static_key(
                dht_signing_key.as_bytes(),
            ).map_err(|e| MiasmaError::KeyDerivation(format!("onion key: {e}")))?;
            *derived
        };
        let onion_static_pubkey = {
            let secret = x25519_dalek::StaticSecret::from(onion_static_secret);
            *x25519_dalek::PublicKey::from(&secret).as_bytes()
        };

        // Initialise issuer registry in bootstrap mode (all verified peers are issuers).
        let mut issuer_registry = IssuerRegistry::new(true);
        // Register ourselves as an issuer.
        issuer_registry.add_issuer(credential_issuer.pubkey_bytes());

        Ok(Self {
            local_peer_id,
            node_type,
            swarm,
            shutdown_tx,
            shutdown_rx,
            dht_tx,
            dht_rx,
            share_tx,
            share_rx,
            pending_puts: HashMap::new(),
            pending_gets: HashMap::new(),
            pending_share_fetches: HashMap::new(),
            pending_admissions: HashMap::new(),
            local_store: None,
            replication_success_tx: None,
            topology_tx: None,
            allow_local_addresses: allow_local,
            local_pow,
            peer_registry: PeerRegistry::new(),
            dht_signing_key,
            pending_peer_addrs: HashMap::new(),
            routing_table: RoutingTable::new(!allow_local),
            event_tick: 0,
            credential_issuer,
            bbs_issuer,
            bbs_issuer_key,
            bbs_wallet: BbsCredentialWallet::new(),
            bbs_issuer_registry: BbsIssuerRegistry::new(),
            credential_wallet: CredentialWallet::new(),
            issuer_registry,
            descriptor_store: DescriptorStore::new(),
            admission_policy: HybridAdmissionPolicy::default(),
            resource_profile: ResourceProfile::Desktop,
            nat_publicly_reachable: false,
            pending_credential_reqs: HashMap::new(),
            pending_descriptor_reqs: HashMap::new(),
            onion_static_secret,
            onion_static_pubkey,
            pending_onion_relays: HashMap::new(),
            pending_onion_replies: HashMap::new(),
            pending_onion_inbound_channels: HashMap::new(),
        })
    }

    /// Attach a local share store so this node can serve inbound shard requests.
    pub fn set_store(&mut self, store: Arc<LocalShareStore>) {
        self.local_store = Some(store);
    }

    /// Set a channel to receive notifications when a Kademlia PUT is acknowledged.
    pub fn set_replication_notifier(&mut self, tx: mpsc::Sender<[u8; 32]>) {
        self.replication_success_tx = Some(tx);
    }

    /// Set a channel to receive topology change events (peer connect/disconnect).
    pub fn set_topology_notifier(&mut self, tx: mpsc::Sender<super::types::TopologyEvent>) {
        self.topology_tx = Some(tx);
    }

    /// Allow loopback/private addresses (for local testing only).
    pub fn set_allow_local_addresses(&mut self, allow: bool) {
        self.allow_local_addresses = allow;
    }

    /// Returns a sender that drives DHT PUT/GET via the Kademlia event loop.
    pub fn dht_handle(&self) -> DhtHandle {
        DhtHandle { tx: self.dht_tx.clone() }
    }

    /// Returns a sender that drives outbound share-fetch requests.
    pub fn share_exchange_handle(&self) -> ShareExchangeHandle {
        ShareExchangeHandle { tx: self.share_tx.clone() }
    }

    /// Register a bootstrap peer in the Kademlia routing table and dial it.
    ///
    /// Explicitly dialing ensures the QUIC connection is established as soon
    /// as the event loop starts, rather than waiting for Kademlia's first
    /// outbound query to trigger the dial.
    pub fn add_bootstrap_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
        // Explicit dial so the QUIC connection is in flight from loop start.
        let p2p_addr = addr.clone().with(libp2p::multiaddr::Protocol::P2p(peer_id));
        if let Err(e) = self.swarm.dial(p2p_addr) {
            debug!("bootstrap dial queued error (may be harmless): {e}");
        }
        info!("Bootstrap peer added + dial queued: {peer_id} @ {addr}");
    }

    /// Register a relay server for NAT traversal.
    pub fn add_relay_server(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
        let peer_id_str = peer_id.to_string();
        let addr_str = addr.to_string();
        let relay_addr = addr
            .with(libp2p::multiaddr::Protocol::P2p(peer_id))
            .with(libp2p::multiaddr::Protocol::P2pCircuit);
        if let Err(e) = self.swarm.dial(relay_addr) {
            debug!("relay dial failed for {peer_id_str}: {e}");
        } else {
            info!("Relay server registered: {peer_id_str} @ {addr_str}");
        }
    }

    /// Initiate Kademlia bootstrap.
    pub fn bootstrap_dht(&mut self) -> Result<(), MiasmaError> {
        self.swarm
            .behaviour_mut()
            .kademlia
            .bootstrap()
            .map_err(|e| MiasmaError::Sss(format!("DHT bootstrap: {e:?}")))?;
        Ok(())
    }

    /// Clone of the shutdown sender — send `()` to stop the event loop.
    pub fn shutdown_handle(&self) -> mpsc::Sender<()> {
        self.shutdown_tx.clone()
    }

    /// Poll the swarm briefly to collect `NewListenAddr` events.
    ///
    /// Call this after `new()` to discover the OS-assigned port when
    /// listening on port 0. Blocks for up to `timeout_ms` milliseconds.
    ///
    /// Uses `tokio::select!` rather than `tokio::time::timeout` so that
    /// each `swarm.next()` poll completes cleanly before the deadline
    /// check runs — avoiding the cancel-unsafety of dropping a
    /// mid-poll swarm future inside `timeout`.
    pub async fn collect_listen_addrs(&mut self, timeout_ms: u64) -> Vec<Multiaddr> {
        let mut addrs = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        let sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                biased;
                event = self.swarm.next() => {
                    match event {
                        Some(SwarmEvent::NewListenAddr { address, .. }) => {
                            addrs.push(address);
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
                _ = &mut sleep => break,
            }
        }
        addrs
    }

    /// Run the node event loop. Blocks until shutdown or error.
    pub async fn run(&mut self) -> Result<(), MiasmaError> {
        loop {
            tokio::select! {
                event = self.swarm.next() => {
                    match event {
                        Some(ev) => self.handle_event(ev),
                        None => break,
                    }
                }
                cmd = self.dht_rx.recv() => {
                    if let Some(cmd) = cmd { self.handle_dht_command(cmd); }
                }
                cmd = self.share_rx.recv() => {
                    if let Some(cmd) = cmd { self.handle_share_command(cmd); }
                }
                _ = self.shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    break;
                }
            }
        }
        Ok(())
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn handle_dht_command(&mut self, cmd: DhtCommand) {
        match cmd {
            DhtCommand::Put { key, value, reply } => {
                // Wrap the raw value in a SignedDhtRecord envelope.
                let signed = SignedDhtRecord::sign(
                    key.clone(),
                    value,
                    &self.dht_signing_key,
                );
                let signed_bytes = bincode::serialize(&signed).unwrap_or_default();

                let record = kad::Record {
                    key: kad::RecordKey::new(&key),
                    value: signed_bytes,
                    publisher: None,
                    expires: None,
                };
                // Always store locally first so remote peers can retrieve the
                // record via GET even if no other peers are reachable yet.
                let _ = self.swarm.behaviour_mut().kademlia.store_mut().put(record.clone());
                // Fire-and-forget network replication: reply success immediately.
                let _ = self.swarm.behaviour_mut().kademlia.put_record(record, kad::Quorum::One);
                let _ = reply.send(Ok(()));
            }
            DhtCommand::Get { key, reply } => {
                let qid = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .get_record(kad::RecordKey::new(&key));
                self.pending_gets.insert(qid, (reply, None));
            }
            DhtCommand::AddBootstrapPeer { peer_id, addr, reply } => {
                self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                self.swarm.add_peer_address(peer_id, addr.clone());
                let p2p_addr = addr.with(libp2p::multiaddr::Protocol::P2p(peer_id));
                if let Err(e) = self.swarm.dial(p2p_addr) {
                    debug!("bootstrap dial queued error (may be harmless): {e}");
                }
                let _ = reply.send(());
            }
            DhtCommand::BootstrapDht { reply } => {
                let result = self
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .bootstrap()
                    .map(|_| ())
                    .map_err(|e| MiasmaError::Sss(format!("DHT bootstrap: {e:?}")));
                let _ = reply.send(result);
            }
            DhtCommand::GetPeerCount { reply } => {
                let count = self.swarm.connected_peers().count();
                let _ = reply.send(count);
            }
            DhtCommand::GetAdmissionStats { reply } => {
                let stats = self.peer_registry.stats();
                let _ = reply.send(stats);
            }
            DhtCommand::GetRoutingStats { reply } => {
                let stats = self.routing_table.stats();
                let _ = reply.send(stats);
            }
            DhtCommand::GetCredentialStats { reply } => {
                // Touch bbs_issuer_key to suppress dead-code warning;
                // the key bytes will be served over BBS+ exchange in future.
                let _bbs_pk_bytes = self.bbs_issuer_key.pk_bytes();
                let stats = CredentialStats {
                    current_epoch: credential::current_epoch(),
                    held_credentials: self.credential_wallet.credential_count(),
                    best_tier: self.credential_wallet.best_credential()
                        .map(|c| c.body.tier.to_string()),
                    known_issuers: self.issuer_registry.issuer_count(),
                    bootstrap_mode: self.issuer_registry.bootstrap_mode,
                };
                let _ = reply.send(stats);
            }
            DhtCommand::GetDescriptorStats { reply } => {
                let stats = self.descriptor_store.stats();
                let _ = reply.send(stats);
            }
            DhtCommand::GetPathSelectionStats { reply } => {
                let relay_descs = self.descriptor_store.relay_descriptors();
                let prefixes: std::collections::HashSet<_> = relay_descs
                    .iter()
                    .filter_map(|d| d.addresses.first())
                    .filter_map(|a| a.parse().ok())
                    .map(|a: Multiaddr| routing::ip_prefix_of(&a))
                    .collect();
                let stats = PathSelectionStats {
                    default_policy: "opportunistic".to_string(),
                    available_relays: relay_descs.len(),
                    relay_prefix_diversity: prefixes.len(),
                };
                let _ = reply.send(stats);
            }
            DhtCommand::GetOutcomeMetrics { reply } => {
                // Onion routing state is tracked at coordinator level;
                // the node reports false here and the daemon can override.
                let onion_enabled = false;
                let metrics = super::metrics::OutcomeMetrics::compute(
                    &self.descriptor_store,
                    &self.peer_registry,
                    &self.routing_table,
                    onion_enabled,
                );
                let _ = reply.send(metrics);
            }
            DhtCommand::GetRelayPeers { reply } => {
                let relays = self.descriptor_store.relay_peer_info();
                let _ = reply.send(relays);
            }
            DhtCommand::GetRelayOnionInfo { reply } => {
                let relays = self.descriptor_store.relay_onion_info();
                let _ = reply.send(relays);
            }
            DhtCommand::SendOnionRequest { peer_id, addrs, request, return_key, reply } => {
                // Register addresses so libp2p can dial the peer.
                for addr_str in &addrs {
                    if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                        self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                        self.swarm.add_peer_address(peer_id, addr.clone());
                    }
                }
                let req_id = self.swarm.behaviour_mut().onion_relay.send_request(&peer_id, request);
                // Store both the return_key and the reply channel.
                // We use pending_onion_relays for the return_key;
                // store the reply sender in a separate map keyed by req_id.
                self.pending_onion_relays.insert(req_id, return_key);
                // We need to store the reply sender too — let's use the pending_onion_replies map.
                self.pending_onion_replies.insert(req_id, reply);
            }
            DhtCommand::GetOnionPubkey { reply } => {
                let _ = reply.send(self.onion_static_pubkey);
            }
            DhtCommand::GetNatStatus { reply } => {
                let _ = reply.send(self.nat_publicly_reachable);
            }
        }
    }

    fn handle_share_command(&mut self, cmd: ShareCommand) {
        let ShareCommand { peer_id, addrs, request, reply } = cmd;

        // Register addresses with both Kademlia (routing) and share_exchange
        // (address book used by request_response when it dials the peer).
        for addr_str in &addrs {
            if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                self.swarm.add_peer_address(peer_id, addr.clone());
            }
        }

        let req_id = self.swarm.behaviour_mut().share_exchange.send_request(&peer_id, request);
        self.pending_share_fetches.insert(req_id, reply);
    }

    fn handle_event(&mut self, event: SwarmEvent<MiasmaBehaviourEvent>) {
        // Periodic network-size observation for difficulty adjustment.
        // Every ~500 events, sample the connected peer count and adjust difficulty.
        self.event_tick = self.event_tick.wrapping_add(1);
        if self.event_tick % 500 == 0 {
            let peer_count = self.swarm.connected_peers().count();
            self.routing_table.observe_network_size(peer_count);
            if let Some(new_diff) = self.routing_table.maybe_adjust_difficulty() {
                info!("routing.difficulty_changed bits={new_diff}");
            }
        }
        // Epoch rotation check (every ~1000 events).
        if self.event_tick % 1000 == 0 {
            let rotated = self.credential_wallet.maybe_rotate();
            if rotated {
                let new_epoch = self.credential_wallet.epoch();
                info!("credential.epoch_rotated epoch={new_epoch}");

                // Notify descriptor store of epoch change for churn tracking.
                self.descriptor_store.on_epoch_rotate(new_epoch);

                // Re-request credentials from verified peers using the new identity.
                let verified_peers = self.peer_registry.verified_peers();
                for peer_id in &verified_peers {
                    let cred_req = CredentialRequest {
                        ephemeral_pubkey: self.credential_wallet.ephemeral_pubkey(),
                        holder_tag: self.credential_wallet.holder_tag(),
                        epoch: self.credential_wallet.epoch(),
                        bbs_link_secret: Some(self.bbs_wallet.link_secret()),
                    };
                    let req_id = self.swarm.behaviour_mut()
                        .credential_exchange
                        .send_request(peer_id, cred_req);
                    self.pending_credential_reqs.insert(req_id, *peer_id);
                }
                // Also prune BBS+ credentials from expired epochs.
                let min_epoch = self.credential_wallet.epoch().saturating_sub(1);
                self.bbs_wallet.prune_before_epoch(min_epoch);
                info!("credential.re_requested peers={}", verified_peers.len());
            }
            let pruned = self.descriptor_store.prune_stale();
            if pruned > 0 {
                info!("descriptor.pruned_stale count={pruned}");
            }
            // Refresh and broadcast our own descriptor on epoch rotation
            // or periodically (every 5000 ticks) to keep it non-stale.
            if rotated || self.event_tick % 5000 == 0 {
                let desc = self.build_local_descriptor();
                let pseudonym = desc.pseudonym;
                self.descriptor_store.upsert(desc.clone());
                // Push to all connected peers.
                let peers: Vec<_> = self.swarm.connected_peers().copied().collect();
                for peer in peers {
                    let req = DescriptorRequest { descriptor: Some(desc.clone()) };
                    let req_id = self.swarm.behaviour_mut()
                        .descriptor_exchange
                        .send_request(&peer, req);
                    self.pending_descriptor_reqs.insert(req_id, peer);
                }
                debug!("descriptor.refreshed pseudonym={}", hex::encode(&pseudonym[..8]));
            }
        }

        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {address}");
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                debug!("Connected: {peer_id}");
                self.peer_registry.on_connected(peer_id);
                if let Some(tx) = &self.topology_tx {
                    let _ = tx.try_send(super::types::TopologyEvent::PeerConnected { peer_id });
                }
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                debug!("Disconnected: {peer_id} ({cause:?})");
                self.peer_registry.on_disconnected(&peer_id);
                self.routing_table.remove_peer(&peer_id);
                self.pending_peer_addrs.remove(&peer_id);
                if let Some(tx) = &self.topology_tx {
                    let _ = tx.try_send(super::types::TopologyEvent::PeerDisconnected { peer_id });
                }
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Identify(
                identify::Event::Received { peer_id, info, .. },
            )) => {
                self.handle_identify(peer_id, info);
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Kademlia(ev)) => {
                self.handle_kad_event(ev);
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::ShareExchange(ev)) => {
                self.handle_share_exchange_event(ev);
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Admission(ev)) => {
                self.handle_admission_event(ev);
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::CredentialExchange(ev)) => {
                self.handle_credential_exchange_event(ev);
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::DescriptorExchange(ev)) => {
                self.handle_descriptor_exchange_event(ev);
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::OnionRelay(ev)) => {
                self.handle_onion_relay_event(ev);
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Autonat(ev)) => match &ev {
                autonat::Event::StatusChanged { old, new } => {
                    info!("AutoNAT: {old:?} → {new:?}");
                    // Track whether we're publicly reachable — drives can_relay in descriptors.
                    self.nat_publicly_reachable = matches!(new, autonat::NatStatus::Public(_));
                }
                _ => debug!("AutoNAT: {ev:?}"),
            },
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Dcutr(ev)) => {
                debug!("DCUtR: {ev:?}");
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Relay(ev)) => {
                debug!("Relay client: {ev:?}");
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Ping(_)) => {}
            _ => {}
        }
    }

    /// Handle Identify protocol completion for a peer.
    fn handle_identify(&mut self, peer_id: PeerId, info: identify::Info) {
        // Filter addresses: reject loopback, link-local, private, unknown.
        // In local/test mode, skip filtering to allow loopback addresses.
        let addrs_to_use = if self.allow_local_addresses {
            info.listen_addrs.clone()
        } else {
            super::address::filter_peer_addresses(&peer_id, &info.listen_addrs)
        };

        if addrs_to_use.is_empty() {
            debug!("admission.rejected peer={peer_id} reason=no_routable_addresses");
            self.peer_registry.record_rejection();
            return;
        }

        // Promote to Observed in peer registry.
        self.peer_registry.on_identify(peer_id);

        if self.allow_local_addresses {
            // Local mode: skip PoW admission, add directly to Kademlia and
            // auto-promote to Verified.
            for addr in &addrs_to_use {
                self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
            }
            if let Some(first_addr) = addrs_to_use.first() {
                self.swarm.behaviour_mut().autonat.add_server(peer_id, Some(first_addr.clone()));
            }
            // Auto-promote: in local mode, treat as verified.
            let fake_pow = self.local_pow.clone();
            self.peer_registry.on_admission_verified(peer_id, fake_pow);

            if let Some(tx) = &self.topology_tx {
                let _ = tx.try_send(super::types::TopologyEvent::PeerRoutable { peer_id });
            }
        } else {
            // Production mode: check IP diversity before proceeding.
            match self.routing_table.check_diversity(&addrs_to_use) {
                Err(violation) => {
                    warn!("routing.diversity_rejected peer={peer_id} reason={violation}");
                    self.routing_table.record_diversity_rejection();
                    self.peer_registry.record_rejection();
                    return;
                }
                Ok(_prefix) => {}
            }

            // Hold addresses pending admission verification.
            // Register addresses in the swarm address book so the admission
            // protocol can dial the peer, but do NOT add to Kademlia yet.
            for addr in &addrs_to_use {
                self.swarm.add_peer_address(peer_id, addr.clone());
            }
            self.pending_peer_addrs.insert(peer_id, addrs_to_use);

            // Initiate PoW admission exchange.
            let req = AdmissionRequest { pow: self.local_pow.clone() };
            let req_id = self.swarm.behaviour_mut().admission.send_request(&peer_id, req);
            self.pending_admissions.insert(req_id, peer_id);
            debug!("admission.requested peer={peer_id}");
        }
    }

    /// Verify a remote peer's PoW proof using the hybrid admission policy.
    ///
    /// Phase 4b: combines PoW, diversity, and credential signals instead of
    /// binary PoW-only check. Credential and reachability signals are added
    /// when available.
    fn verify_remote_pow(&self, peer_id: &PeerId, pow: &NodeIdPoW) -> Result<(), RejectionReason> {
        // Check that the PoW pubkey matches the peer's libp2p identity.
        let ed_pubkey = libp2p::identity::ed25519::PublicKey::try_from_bytes(&pow.pubkey)
            .map_err(|_| RejectionReason::MalformedPoW)?;
        let libp2p_pubkey = libp2p::identity::PublicKey::from(ed_pubkey);
        let claimed_peer_id = PeerId::from(libp2p_pubkey);

        if &claimed_peer_id != peer_id {
            return Err(RejectionReason::PubkeyMismatch);
        }

        // Compute PoW difficulty (leading_zeros returns u32, admission expects u8).
        let pow_difficulty = sybil::leading_zeros(&pow.hash).min(255) as u8;

        // Check diversity: is this prefix unique?
        let unique_prefix = self.pending_peer_addrs
            .get(peer_id)
            .and_then(|addrs| addrs.first())
            .map(|a| self.routing_table.check_diversity(std::slice::from_ref(a)).is_ok())
            .unwrap_or(false);

        // Check if we have a credential for this peer (from a previous exchange).
        // Prefer BBS+ tier (privacy-preserving) over Ed25519 tier; fall back to Ed25519.
        let descriptor = self.descriptor_store.get_by_peer(peer_id);
        let credential_tier = descriptor
            .and_then(|d| d.bbs_tier())
            .or_else(|| descriptor
                .and_then(|d| d.credential.as_ref())
                .map(|c| c.credential.body.tier));

        // Evaluate using hybrid admission policy.
        let signals = AdmissionSignals {
            pow_difficulty,
            unique_prefix,
            reachable: true, // peer connected and sent us a message
            credential_tier,
            resource_profile: ResourceProfile::Desktop, // default until descriptor received
        };

        let decision = self.admission_policy.evaluate(&signals);
        if decision.admitted {
            Ok(())
        } else {
            match decision.rejection_reason {
                Some(super::admission_policy::HybridRejection::InsufficientMinPoW { .. }) => {
                    Err(RejectionReason::InsufficientDifficulty)
                }
                _ => Err(RejectionReason::InsufficientDifficulty),
            }
        }
    }

    /// Handle admission protocol events.
    fn handle_admission_event(
        &mut self,
        ev: request_response::Event<AdmissionRequest, AdmissionResponse>,
    ) {
        match ev {
            // Inbound admission request: verify their PoW, respond with ours.
            request_response::Event::Message {
                peer,
                message: request_response::Message::Request { request, channel, .. },
            } => {
                // Verify the requester's PoW.
                match self.verify_remote_pow(&peer, &request.pow) {
                    Ok(()) => {
                        info!("admission.inbound_verified peer={peer}");
                        // Respond with our own PoW.
                        let resp = AdmissionResponse { pow: self.local_pow.clone() };
                        let _ = self.swarm.behaviour_mut().admission.send_response(channel, resp);

                        // Promote the peer to Verified and add to Kademlia.
                        self.promote_peer_to_verified(peer, request.pow);
                    }
                    Err(reason) => {
                        warn!("admission.rejected peer={peer} reason={reason}");
                        self.peer_registry.record_rejection();
                        // Still respond (protocol requires it) but peer won't be promoted.
                        let resp = AdmissionResponse { pow: self.local_pow.clone() };
                        let _ = self.swarm.behaviour_mut().admission.send_response(channel, resp);
                    }
                }
            }
            // Outbound admission response received: verify their PoW.
            request_response::Event::Message {
                peer,
                message: request_response::Message::Response { request_id, response },
            } => {
                self.pending_admissions.remove(&request_id);
                match self.verify_remote_pow(&peer, &response.pow) {
                    Ok(()) => {
                        info!("admission.verified peer={peer}");
                        self.promote_peer_to_verified(peer, response.pow);
                    }
                    Err(reason) => {
                        warn!("admission.rejected peer={peer} reason={reason}");
                        self.peer_registry.record_rejection();
                    }
                }
            }
            request_response::Event::OutboundFailure { request_id, peer, error } => {
                self.pending_admissions.remove(&request_id);
                warn!("admission.outbound_failure peer={peer} error={error}");
                self.peer_registry.record_rejection();
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                warn!("admission.inbound_failure peer={peer} error={error}");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    /// Promote a peer to Verified: add addresses to Kademlia, issue credential,
    /// publish descriptor, signal routable.
    fn promote_peer_to_verified(&mut self, peer_id: PeerId, pow: NodeIdPoW) {
        self.peer_registry.on_admission_verified(peer_id, pow.clone());

        // Promote held addresses to Kademlia routing table.
        let addrs = self.pending_peer_addrs.remove(&peer_id).unwrap_or_default();
        if !addrs.is_empty() {
            let prefix = routing::ip_prefix_of(addrs.first().unwrap_or(
                &"/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            ));
            self.routing_table.add_peer(peer_id, prefix);

            for addr in &addrs {
                self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
            }
            if let Some(first_addr) = addrs.first() {
                self.swarm.behaviour_mut().autonat.add_server(peer_id, Some(first_addr.clone()));
            }
        }

        // ── Phase 4b: credential issuance ────────────────────────────────
        // In bootstrap mode, register this peer's PoW pubkey as a potential issuer.
        if self.issuer_registry.bootstrap_mode {
            self.issuer_registry.add_issuer(pow.pubkey);
            // Also register their BBS+ issuer key (derived from same PoW pubkey seed).
            // In bootstrap mode, we assume all verified peers are also BBS+ issuers.
            let bbs_seed = blake3::hash(
                &[b"miasma-bbs-issuer-v1".as_slice(), &pow.pubkey].concat(),
            );
            let remote_bbs_key = BbsIssuerKey::from_seed(bbs_seed.as_bytes());
            self.bbs_issuer_registry.add_issuer(remote_bbs_key.pk_bytes());
        }

        // Initiate credential exchange: request a credential from the new peer,
        // and they can request one from us via the protocol.
        let cred_req = CredentialRequest {
            ephemeral_pubkey: self.credential_wallet.ephemeral_pubkey(),
            holder_tag: self.credential_wallet.holder_tag(),
            epoch: self.credential_wallet.epoch(),
            bbs_link_secret: Some(self.bbs_wallet.link_secret()),
        };
        let req_id = self.swarm.behaviour_mut().credential_exchange.send_request(&peer_id, cred_req);
        self.pending_credential_reqs.insert(req_id, peer_id);

        // ── Phase 4b: descriptor exchange ────────────────────────────────
        // Build our own descriptor and send it to the new peer.
        let our_desc = self.build_local_descriptor();
        let desc_req = DescriptorRequest { descriptor: Some(our_desc) };
        let req_id = self.swarm.behaviour_mut().descriptor_exchange.send_request(&peer_id, desc_req);
        self.pending_descriptor_reqs.insert(req_id, peer_id);

        // Signal that this peer is now routable.
        if let Some(tx) = &self.topology_tx {
            let _ = tx.try_send(super::types::TopologyEvent::PeerRoutable { peer_id });
        }
    }

    /// Build this node's peer descriptor for publication.
    fn build_local_descriptor(&self) -> PeerDescriptor {
        let pseudonym = self.credential_wallet.holder_tag();
        let addresses: Vec<String> = self.swarm.listeners()
            .map(|a| a.to_string())
            .collect();

        let credential_presentation = self.credential_wallet.present(
            &self.local_peer_id.to_bytes(),
        );

        // Attach a BBS+ proof if we hold a BBS+ credential.
        // Default policy reveals tier only — sufficient for admission scoring.
        let bbs_proof = self.bbs_wallet.present(
            &DisclosurePolicy::default(),
            &self.local_peer_id.to_bytes(),
        );

        PeerDescriptor::new_signed_full(
            pseudonym,
            ReachabilityKind::Direct,
            addresses,
            PeerCapabilities {
                can_store: true,
                can_relay: self.nat_publicly_reachable,
                can_route: true,
                can_issue: true, // in bootstrap mode, all verified nodes can issue
                bandwidth_class: 2, // medium
            },
            self.resource_profile,
            credential_presentation,
            bbs_proof,
            Some(self.onion_static_pubkey),
            self.credential_wallet.epoch(),
            &self.dht_signing_key,
        )
    }

    /// Handle credential exchange protocol events.
    fn handle_credential_exchange_event(
        &mut self,
        ev: request_response::Event<CredentialRequest, CredentialResponse>,
    ) {
        match ev {
            // Inbound: peer requests a credential from us.
            request_response::Event::Message {
                peer,
                message: request_response::Message::Request { request, channel, .. },
            } => {
                // Only issue credentials to verified peers.
                let (credential, bbs_credential) = if self.peer_registry.is_verified(&peer) {
                    let cred = self.credential_issuer.issue(
                        CredentialTier::Verified,
                        request.epoch,
                        CAP_STORE | CAP_ROUTE,
                        request.holder_tag,
                    );
                    // Issue BBS+ credential with the requester's link secret.
                    let bbs_cred = request.bbs_link_secret.map(|link_secret| {
                        self.bbs_issuer.issue(BbsCredentialAttributes {
                            link_secret,
                            tier: CredentialTier::Verified,
                            capabilities: CAP_STORE | CAP_ROUTE,
                            epoch: request.epoch,
                            nonce: rand::random(),
                        })
                    });
                    info!("credential.issued peer={peer} tier=Verified epoch={} ed25519=true bbs+={}", request.epoch, bbs_cred.is_some());
                    (Some(cred), bbs_cred)
                } else {
                    debug!("credential.denied peer={peer} reason=not_verified");
                    (None, None)
                };
                let resp = CredentialResponse { credential, bbs_credential };
                let _ = self.swarm.behaviour_mut().credential_exchange.send_response(channel, resp);
            }
            // Outbound: we received a credential from a peer.
            request_response::Event::Message {
                peer,
                message: request_response::Message::Response { request_id, response },
            } => {
                self.pending_credential_reqs.remove(&request_id);
                if let Some(cred) = response.credential {
                    // Verify the credential before storing:
                    // 1. Check issuer is known
                    // 2. Check issuer signature is valid
                    // 3. Check holder tag matches our wallet identity
                    // 4. Check epoch is fresh
                    let issuer_list = self.issuer_registry.issuer_list();
                    let epoch = credential::current_epoch();

                    // Verify the credential's issuer signature and freshness.
                    let context = self.local_peer_id.to_bytes();
                    let presentation = CredentialPresentation::create(
                        &cred,
                        &self.credential_wallet.identity(),
                        &context,
                    );
                    match credential::verify_presentation(
                        &presentation,
                        &context,
                        &issuer_list,
                        epoch,
                        CredentialTier::Observed, // accept any tier
                    ) {
                        Ok(_) => {
                            self.credential_wallet.store(cred.clone());
                            info!("credential.verified_and_stored peer={peer} tier={} epoch={}", cred.body.tier, cred.body.epoch);
                        }
                        Err(e) => {
                            warn!("credential.rejected peer={peer} error={e}");
                        }
                    }
                }
                // Verify and store BBS+ credential if present.
                if let Some(bbs_cred) = response.bbs_credential {
                    let issuer_pk = &bbs_cred.issuer_pk;
                    if issuer_pk.len() == 96 {
                        let mut pk_arr = [0u8; 96];
                        pk_arr.copy_from_slice(issuer_pk);
                        if self.bbs_issuer_registry.is_known(&pk_arr) {
                            // Verify the BBS+ credential by creating and verifying a proof.
                            let context = self.local_peer_id.to_bytes();
                            let proof = bbs_create_proof(&bbs_cred, &DisclosurePolicy::default(), &context);
                            match bbs_verify_proof(&proof, &pk_arr, &context) {
                                Ok(disclosed) => {
                                    let tier_val = disclosed.iter()
                                        .find(|&&(i, _)| i == 1)
                                        .map(|&(_, v)| v)
                                        .unwrap_or(0);
                                    self.bbs_wallet.store(bbs_cred);
                                    info!("bbs_credential.verified_and_stored peer={peer} tier_val={tier_val}");
                                }
                                Err(e) => {
                                    warn!("bbs_credential.rejected peer={peer} error={e}");
                                }
                            }
                        } else {
                            debug!("bbs_credential.skipped peer={peer} reason=unknown_issuer");
                        }
                    }
                }
            }
            request_response::Event::OutboundFailure { request_id, peer, error } => {
                self.pending_credential_reqs.remove(&request_id);
                debug!("credential.outbound_failure peer={peer} error={error}");
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                debug!("credential.inbound_failure peer={peer} error={error}");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    /// Handle descriptor exchange protocol events.
    fn handle_descriptor_exchange_event(
        &mut self,
        ev: request_response::Event<DescriptorRequest, DescriptorResponse>,
    ) {
        match ev {
            // Inbound: peer sends us their descriptor.
            request_response::Event::Message {
                peer,
                message: request_response::Message::Request { request, channel, .. },
            } => {
                // Store their descriptor if signature is valid.
                if let Some(desc) = request.descriptor {
                    if desc.verify_self() {
                        self.descriptor_store.register_peer_pseudonym(peer, desc.pseudonym);
                        if self.descriptor_store.upsert(desc) {
                            debug!("descriptor.received peer={peer}");
                        }
                    } else {
                        warn!("descriptor.rejected_invalid_signature peer={peer}");
                    }
                }
                // Respond with our own descriptor.
                let our_desc = self.build_local_descriptor();
                let resp = DescriptorResponse { descriptor: Some(our_desc) };
                let _ = self.swarm.behaviour_mut().descriptor_exchange.send_response(channel, resp);
            }
            // Outbound: we received a descriptor from a peer.
            request_response::Event::Message {
                peer,
                message: request_response::Message::Response { request_id, response },
            } => {
                self.pending_descriptor_reqs.remove(&request_id);
                if let Some(desc) = response.descriptor {
                    if desc.verify_self() {
                        self.descriptor_store.register_peer_pseudonym(peer, desc.pseudonym);
                        if self.descriptor_store.upsert(desc) {
                            debug!("descriptor.received peer={peer}");
                        }
                    } else {
                        warn!("descriptor.rejected_invalid_signature peer={peer}");
                    }
                }
            }
            request_response::Event::OutboundFailure { request_id, peer, error } => {
                self.pending_descriptor_reqs.remove(&request_id);
                debug!("descriptor.outbound_failure peer={peer} error={error}");
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                debug!("descriptor.inbound_failure peer={peer} error={error}");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    /// Handle onion relay protocol events.
    ///
    /// Three roles a node can play:
    /// 1. **R1 (outer relay)**: receives OnionPacket, peels outer layer, forwards inner to R2
    /// 2. **R2 (inner relay)**: receives Forward cell, peels inner layer, delivers body to Target
    /// 3. **Target**: receives Deliver, decrypts e2e body, processes share request, responds
    ///
    /// On the outbound side, handles responses from relay sub-requests.
    fn handle_onion_relay_event(
        &mut self,
        ev: request_response::Event<OnionRelayRequest, OnionRelayResponse>,
    ) {
        match ev {
            request_response::Event::Message {
                peer,
                message: request_response::Message::Request { request, channel, .. },
            } => {
                debug!("onion_relay.inbound from={peer} variant={}", match &request {
                    OnionRelayRequest::Packet { .. } => "Packet",
                    OnionRelayRequest::Forward { .. } => "Forward",
                    OnionRelayRequest::Deliver { .. } => "Deliver",
                });
                match request {
                    OnionRelayRequest::Packet { circuit_id, layer }
                    | OnionRelayRequest::Forward { circuit_id, layer } => {
                        // Peel one onion layer using our static key.
                        match super::onion_relay::process_onion_layer(
                            &self.onion_static_secret,
                            circuit_id,
                            &layer,
                        ) {
                            Ok(super::onion_relay::OnionRelayAction::ForwardToNext {
                                next_hop_peer_id,
                                circuit_id,
                                inner_layer,
                                return_key,
                            }) => {
                                // R1 role: forward to R2.
                                let next_peer = match PeerId::from_bytes(&next_hop_peer_id) {
                                    Ok(p) => p,
                                    Err(e) => {
                                        warn!("onion_relay: invalid next_hop peer_id: {e}");
                                        let _ = self.swarm.behaviour_mut().onion_relay
                                            .send_response(channel, OnionRelayResponse::Error(
                                                "invalid next_hop peer_id".into(),
                                            ));
                                        return;
                                    }
                                };
                                // Send forward cell to R2.
                                let fwd_req = OnionRelayRequest::Forward {
                                    circuit_id,
                                    layer: inner_layer,
                                };
                                let req_id = self.swarm.behaviour_mut()
                                    .onion_relay.send_request(&next_peer, fwd_req);
                                // Store the return_key so we can encrypt the response,
                                // and store the inbound channel so we can relay the response back.
                                self.pending_onion_relays.insert(req_id, return_key);
                                // Store the inbound response channel for this relay request.
                                self.pending_onion_inbound_channels.insert(req_id, channel);
                            }
                            Ok(super::onion_relay::OnionRelayAction::DeliverToTarget {
                                target_peer_id,
                                circuit_id,
                                body,
                                return_key,
                            }) => {
                                // R2 role: deliver to target.
                                let target = match PeerId::from_bytes(&target_peer_id) {
                                    Ok(p) => p,
                                    Err(e) => {
                                        warn!("onion_relay: invalid target peer_id: {e}");
                                        let _ = self.swarm.behaviour_mut().onion_relay
                                            .send_response(channel, OnionRelayResponse::Error(
                                                "invalid target peer_id".into(),
                                            ));
                                        return;
                                    }
                                };
                                let deliver_req = OnionRelayRequest::Deliver {
                                    circuit_id,
                                    body,
                                };
                                let req_id = self.swarm.behaviour_mut()
                                    .onion_relay.send_request(&target, deliver_req);
                                self.pending_onion_relays.insert(req_id, return_key);
                                self.pending_onion_inbound_channels.insert(req_id, channel);
                            }
                            Err(e) => {
                                warn!("onion_relay: peel failed: {e}");
                                let _ = self.swarm.behaviour_mut().onion_relay
                                    .send_response(channel, OnionRelayResponse::Error(
                                        format!("onion peel failed: {e}"),
                                    ));
                            }
                        }
                    }
                    OnionRelayRequest::Deliver { body, .. } => {
                        // Target role: decrypt e2e body and process share request.
                        let response = self.handle_onion_delivery(&body);
                        let _ = self.swarm.behaviour_mut().onion_relay
                            .send_response(channel, response);
                    }
                }
            }
            request_response::Event::Message {
                message: request_response::Message::Response { request_id, response },
                ..
            } => {
                // Response from a sub-request (R1→R2 or R2→Target).
                if let Some(return_key) = self.pending_onion_relays.remove(&request_id) {
                    if let Some(inbound_channel) = self.pending_onion_inbound_channels.remove(&request_id) {
                        // We're a relay: encrypt the response with our return_key and forward back.
                        let relay_response = match response {
                            OnionRelayResponse::Data(data) => {
                                match super::onion_relay::encrypt_relay_response(&return_key, &data) {
                                    Ok(encrypted) => OnionRelayResponse::Data(encrypted),
                                    Err(e) => OnionRelayResponse::Error(format!("relay encrypt failed: {e}")),
                                }
                            }
                            OnionRelayResponse::Error(e) => OnionRelayResponse::Error(e),
                        };
                        let _ = self.swarm.behaviour_mut().onion_relay
                            .send_response(inbound_channel, relay_response);
                    } else if let Some(reply) = self.pending_onion_replies.remove(&request_id) {
                        // We're the initiator: return the response to the coordinator.
                        let _ = reply.send(Ok(response));
                    }
                } else if let Some(reply) = self.pending_onion_replies.remove(&request_id) {
                    // Initiator path: no return_key stored (direct delivery response).
                    let _ = reply.send(Ok(response));
                }
            }
            request_response::Event::OutboundFailure { request_id, peer, error } => {
                warn!("onion_relay.outbound_failure peer={peer} error={error}");
                // Clean up and propagate error.
                self.pending_onion_relays.remove(&request_id);
                if let Some(channel) = self.pending_onion_inbound_channels.remove(&request_id) {
                    let _ = self.swarm.behaviour_mut().onion_relay
                        .send_response(channel, OnionRelayResponse::Error(
                            format!("relay outbound failure: {error}"),
                        ));
                }
                if let Some(reply) = self.pending_onion_replies.remove(&request_id) {
                    let _ = reply.send(Err(MiasmaError::Network(format!(
                        "onion relay outbound failure: {error}"
                    ))));
                }
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                debug!("onion_relay.inbound_failure peer={peer} error={error}");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    /// Handle an onion delivery at the target node.
    ///
    /// The body format is: `session_key(32) || e2e_encrypted_layer(OnionLayer)`.
    /// The target decrypts the e2e layer with its onion static key to get the
    /// share request, processes it, and returns the response encrypted with
    /// the session key.
    fn handle_onion_delivery(&self, body: &[u8]) -> OnionRelayResponse {
        if body.len() <= 32 {
            return OnionRelayResponse::Error("delivery body too short".into());
        }

        let session_key: [u8; 32] = match body[..32].try_into() {
            Ok(k) => k,
            Err(_) => return OnionRelayResponse::Error("invalid session key".into()),
        };

        // Deserialize the e2e OnionLayer.
        let e2e_layer: crate::onion::packet::OnionLayer = match bincode::deserialize(&body[32..]) {
            Ok(l) => l,
            Err(e) => return OnionRelayResponse::Error(format!("bad e2e layer: {e}")),
        };

        // Decrypt with our onion static key.
        let payload = match crate::onion::packet::OnionLayerProcessor::peel(
            &self.onion_static_secret,
            &e2e_layer,
        ) {
            Ok(p) => p,
            Err(e) => return OnionRelayResponse::Error(format!("e2e decrypt failed: {e}")),
        };

        // payload.data is the share request body (tag byte + bincode ShareFetchRequest).
        let share_response = match self.process_onion_share_request(&payload.data) {
            Ok(resp) => resp,
            Err(e) => return OnionRelayResponse::Error(format!("share request failed: {e}")),
        };

        // Encrypt the response with the session key for e2e return privacy.
        match crate::onion::packet::encrypt_response(&session_key, &share_response) {
            Ok(encrypted) => OnionRelayResponse::Data(encrypted),
            Err(e) => OnionRelayResponse::Error(format!("response encrypt failed: {e}")),
        }
    }

    /// Process a share request received via onion delivery.
    ///
    /// Wire format: `0x10` tag + bincode(ShareFetchRequest) → bincode(ShareFetchResponse)
    fn process_onion_share_request(&self, data: &[u8]) -> Result<Vec<u8>, MiasmaError> {
        if data.is_empty() {
            return Err(MiasmaError::Sss("empty onion share request".into()));
        }
        if data[0] != 0x10 {
            return Err(MiasmaError::Sss(format!("unexpected onion share tag: {}", data[0])));
        }

        let req: ShareFetchRequest = bincode::deserialize(&data[1..])
            .map_err(|e| MiasmaError::Serialization(e.to_string()))?;

        let share = if let Some(store) = &self.local_store {
            let prefix: [u8; 8] = req.mid_digest[..8].try_into().unwrap();
            let candidates = store.search_by_mid_prefix(&prefix);
            candidates.iter().find_map(|addr| {
                store.get(addr).ok().and_then(|s| {
                    if s.slot_index == req.slot_index && s.segment_index == req.segment_index {
                        Some(s)
                    } else {
                        None
                    }
                })
            })
        } else {
            None
        };

        let resp = ShareFetchResponse { share };
        let mut out = vec![0x11u8];
        out.extend(
            bincode::serialize(&resp)
                .map_err(|e| MiasmaError::Serialization(e.to_string()))?,
        );
        Ok(out)
    }

    // (wallet identity is accessed via self.credential_wallet.identity())

    fn handle_kad_event(&mut self, ev: kad::Event) {
        match ev {
            kad::Event::OutboundQueryProgressed { id, result, step, .. } => match result {
                kad::QueryResult::PutRecord(Ok(kad::PutRecordOk { key })) => {
                    // Notify replication tracker: network PUT acknowledged by remote peer.
                    if let Some(tx) = &self.replication_success_tx {
                        let key_bytes = key.as_ref();
                        if key_bytes.len() == 32 {
                            let mut digest = [0u8; 32];
                            digest.copy_from_slice(key_bytes);
                            let _ = tx.try_send(digest);
                        }
                    }
                    // Record successful DHT interaction for all connected peers.
                    for peer_id in self.swarm.connected_peers().cloned().collect::<Vec<_>>() {
                        self.routing_table.record_success(&peer_id);
                    }
                    if let Some(reply) = self.pending_puts.remove(&id) {
                        let _ = reply.send(Ok(()));
                    }
                }
                kad::QueryResult::PutRecord(Err(e)) => {
                    if let Some(reply) = self.pending_puts.remove(&id) {
                        let _ = reply.send(Err(MiasmaError::Dht(format!("{e:?}"))));
                    }
                }
                kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(pr))) => {
                    // Validate signature on retrieved records.
                    let value = pr.record.value;
                    let validated = if let Ok(signed) = bincode::deserialize::<SignedDhtRecord>(&value) {
                        if signed.verify_signature() {
                            // Record successful interaction for the peer that provided this record.
                            if let Some(peer) = pr.peer {
                                self.routing_table.record_success(&peer);
                            }
                            Some(value)
                        } else {
                            warn!("dht.record_rejected reason=invalid_signature key={:?}", pr.record.key);
                            // Record failure for the peer that sent a bad record.
                            if let Some(peer) = pr.peer {
                                self.routing_table.record_failure(&peer);
                            }
                            None
                        }
                    } else {
                        // Accept plain DhtRecord during transition period.
                        Some(value)
                    };

                    if let Some(valid_value) = validated {
                        if let Some((reply, _)) = self.pending_gets.remove(&id) {
                            let _ = reply.send(Ok(Some(valid_value)));
                        }
                    }
                    // If invalid, don't resolve — wait for more results or timeout.
                }
                kad::QueryResult::GetRecord(
                    Ok(kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. }),
                )
                | kad::QueryResult::GetRecord(Err(_)) => {
                    if step.last {
                        if let Some((reply, cached)) = self.pending_gets.remove(&id) {
                            let _ = reply.send(Ok(cached));
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn handle_share_exchange_event(
        &mut self,
        ev: request_response::Event<ShareFetchRequest, ShareFetchResponse>,
    ) {
        match ev {
            // Inbound request: serve from local store.
            request_response::Event::Message {
                message:
                    request_response::Message::Request { request, channel, .. },
                ..
            } => {
                let share = self.local_store.as_ref().and_then(|store| {
                    let prefix: [u8; 8] = request.mid_digest[..8].try_into().ok()?;
                    let candidates = store.search_by_mid_prefix(&prefix);
                    candidates.iter().find_map(|addr| {
                        store.get(addr).ok().and_then(|s| {
                            if s.slot_index == request.slot_index
                                && s.segment_index == request.segment_index
                            {
                                Some(s)
                            } else {
                                None
                            }
                        })
                    })
                });
                let response = ShareFetchResponse { share };
                let _ = self.swarm.behaviour_mut().share_exchange.send_response(channel, response);
            }
            // Outbound response received: resolve pending future.
            request_response::Event::Message {
                message: request_response::Message::Response { request_id, response },
                ..
            } => {
                if let Some(reply) = self.pending_share_fetches.remove(&request_id) {
                    let _ = reply.send(Ok(response.share));
                }
            }
            request_response::Event::OutboundFailure { request_id, error, .. } => {
                warn!("Share fetch outbound failure: {error}");
                if let Some(reply) = self.pending_share_fetches.remove(&request_id) {
                    let _ = reply.send(Err(MiasmaError::Network(error.to_string())));
                }
            }
            request_response::Event::InboundFailure { error, .. } => {
                warn!("Share fetch inbound failure: {error}");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }
}

// ─── Swarm builder ────────────────────────────────────────────────────────────

fn build_swarm(
    keypair: Keypair,
    local_peer_id: PeerId,
    listen_addr: &str,
) -> Result<Swarm<MiasmaBehaviour>, MiasmaError> {
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| MiasmaError::Sss(format!("TCP init failed: {e}")))?
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|e| MiasmaError::Sss(format!("relay client init failed: {e}")))?
        .with_behaviour(|key: &Keypair, relay_client| {
            let store = MemoryStore::new(local_peer_id);
            let kad_config = kad::Config::new(StreamProtocol::new("/miasma/kad/1.0.0"));
            let mut kademlia = kad::Behaviour::with_config(local_peer_id, store, kad_config);
            kademlia.set_mode(Some(kad::Mode::Server));

            let identify =
                identify::Behaviour::new(identify::Config::new("/miasma/id/1.0.0".into(), key.public()));

            let ping = ping::Behaviour::new(
                ping::Config::new().with_interval(Duration::from_secs(30)),
            );

            let autonat = autonat::Behaviour::new(
                local_peer_id,
                autonat::Config {
                    refresh_interval: Duration::from_secs(60),
                    retry_interval: Duration::from_secs(10),
                    ..Default::default()
                },
            );

            let dcutr = dcutr::Behaviour::new(local_peer_id);

            let share_exchange = request_response::Behaviour::<ShareCodec>::new(
                [(
                    StreamProtocol::new("/miasma/share/1.0.0"),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            );

            let admission = request_response::Behaviour::<AdmissionCodec>::new(
                [(
                    StreamProtocol::new("/miasma/admission/1.0.0"),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            );

            let credential_exchange = request_response::Behaviour::<CredentialCodec>::new(
                [(
                    StreamProtocol::new("/miasma/credential/1.0.0"),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            );

            let descriptor_exchange = request_response::Behaviour::<DescriptorCodec>::new(
                [(
                    StreamProtocol::new("/miasma/descriptor/1.0.0"),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            );

            let onion_relay = request_response::Behaviour::<OnionRelayCodec>::new(
                [(
                    StreamProtocol::new("/miasma/onion/1.0.0"),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            );

            Ok(MiasmaBehaviour {
                kademlia,
                identify,
                ping,
                autonat,
                relay: relay_client,
                dcutr,
                share_exchange,
                admission,
                credential_exchange,
                descriptor_exchange,
                onion_relay,
            })
        })
        .map_err(|e| MiasmaError::Sss(format!("behaviour init failed: {e}")))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
        .build();

    let addr: Multiaddr = listen_addr
        .parse()
        .map_err(|e| MiasmaError::Sss(format!("invalid listen addr '{listen_addr}': {e}")))?;
    swarm
        .listen_on(addr)
        .map_err(|e| MiasmaError::Sss(format!("listen_on failed: {e}")))?;

    Ok(swarm)
}
