/// 2-hop onion routing — Phase 1 (in-process) and Phase 2 (real network).
///
/// # Module structure
/// ```text
/// onion/
///   packet.rs   — OnionPacket construction/parsing (pure crypto: X25519 + XChaCha20)
///   circuit.rs  — CircuitId, CircuitState, CircuitManager
///   router.rs   — OnionRelayHandler + InProcessRelay (Phase 1 in-process simulation)
///   executor.rs — LiveOnionDhtExecutor (Phase 1) + NetworkOnionDhtExecutor (Phase 2)
///   share.rs    — OnionShareFetcher trait + LiveOnionShareFetcher (Phase 1)
/// ```
///
/// # Privacy guarantees
/// - **Phase 1** (`LiveOnionDhtExecutor`): Uses `InProcessRelay` — cryptographic
///   correctness is verified but no network-level anonymity (relays simulated).
/// - **Phase 2** (`NetworkOnionDhtExecutor`): Sends onion packets to real relay
///   peers via libp2p QUIC. Provides actual anonymity for DHT operations.
/// - **Coordinator retrieval**: `retrieve_via_onion()` and
///   `retrieve_via_onion_rendezvous()` already use real network relays
///   via `DhtHandle::send_onion_request()`.
pub mod circuit;
pub mod executor;
pub mod packet;
pub mod router;
pub mod share;

pub use circuit::{CircuitManager, RelayInfo};
pub use executor::{LiveOnionDhtExecutor, NetworkOnionDhtExecutor};
pub use packet::{
    derive_onion_static_key, CircuitId, InnerPayload, OnionLayer, OnionLayerProcessor, OnionPacket,
    OnionPacketBuilder, ReturnPath,
};
pub use router::{ForwardCell, InProcessRelay, OnionRelayHandler, ResponseCell};
pub use share::{LiveOnionShareFetcher, OnionShareFetcher};
