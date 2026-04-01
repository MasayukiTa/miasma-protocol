// Suppress clippy lints for structural patterns that would require API-breaking changes.
#![allow(
    clippy::type_complexity,
    clippy::too_many_arguments,
    clippy::inherent_to_string,
    clippy::should_implement_trait,
    clippy::large_enum_variant,
    clippy::len_without_is_empty,
    clippy::new_without_default,
    clippy::if_same_then_else
)]

pub mod config;
pub mod cover_traffic;
pub mod crypto;
pub mod daemon;
pub mod directed;
pub mod dissolution;
pub mod error;
pub mod network;
pub mod onion;
pub mod pipeline;
pub mod repair;
pub mod reputation;
pub mod retrieval;
pub mod secure_file;
pub mod share;
pub mod store;
pub mod transport;

pub use config::{default_data_dir, NodeConfig, TransportConfig};
pub use cover_traffic::{CoverTrafficConfig, CoverTrafficEngine};
pub use crypto::hash::ContentId;
pub use daemon::{
    ipc::{daemon_request, read_port_file, ControlRequest, ControlResponse, DaemonStatus},
    DaemonServer,
};
pub use directed::{
    create_envelope, decrypt_directed_content, decrypt_envelope_payload, derive_content_key,
    finalize_envelope, format_sharing_contact, format_sharing_key, parse_sharing_contact,
    parse_sharing_key, DirectedCodec, DirectedEnvelope, DirectedInbox, DirectedRequest,
    DirectedResponse, EnvelopePayload, EnvelopeState, EnvelopeSummary, RetentionPeriod,
};
pub use dissolution::{
    dissolve_file, retrieve_file, DissolutionManifest, DistributionResult, SegmentMeta,
    ShareDistributor, ShareSink, DEFAULT_SEGMENT_SIZE,
};
pub use error::MiasmaError;
pub use libp2p::{Multiaddr, PeerId};
pub use network::{
    AdmissionPolicyStats, AdmissionStats, AnonymityPolicy, BbsCredential, BbsError, BbsIssuer,
    BbsIssuerKey, BbsPlusScheme, BbsProof, BypassOnionDhtExecutor, CredentialScheme,
    CredentialStats, CredentialTier, CredentialWallet, DescriptorStats, DescriptorStore, DhtHandle,
    DirectDhtExecutor, DisclosurePolicy, DiversityViolation, Ed25519Scheme, HybridAdmissionPolicy,
    IssuerRegistry, MiasmaCoordinator, MiasmaNode, NetworkShareFetcher, NodeType,
    OnionAwareDhtExecutor, OutcomeMetrics, PathSelectionStats, PeerCapabilities, PeerDescriptor,
    PeerRegistry, ReachabilityKind, RejectionReason, ResourceProfile, RoutingStats,
    ShareExchangeHandle, TopologyEvent,
};
pub use onion::{
    CircuitId, CircuitManager, InProcessRelay, LiveOnionDhtExecutor, LiveOnionShareFetcher,
    NetworkOnionDhtExecutor, OnionPacketBuilder, OnionShareFetcher,
};
pub use pipeline::{dissolve, retrieve, DissolutionParams};
pub use retrieval::{
    DhtShareSource, FallbackShareSource, LocalShareSource, RetrievalCoordinator, ShareSource,
    StreamingRetrievalCoordinator,
};
pub use share::{MiasmaShare, ShareVerification};
pub use store::LocalShareStore;
pub use transport::obfuscated::{
    BrowserFingerprint, ObfuscatedConfig, ObfuscatedQuicPayloadTransport, ObfuscatedQuicServer,
};
pub use transport::payload::{
    Libp2pPayloadTransport, PayloadTransport, PayloadTransportError, PayloadTransportKind,
    PayloadTransportSelector, TcpDirectPayloadTransport, TransportAttempt, TransportExhaustedError,
    TransportPhase, TransportReadiness, TransportStats, TransportedShare,
};
pub use transport::proxy::ProxyConfig;
pub use transport::websocket::{WebSocketConfig, WssPayloadTransport, WssShareServer};
pub use transport::{PluggableTransport, TransportSelector};
