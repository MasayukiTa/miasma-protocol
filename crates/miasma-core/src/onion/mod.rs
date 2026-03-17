/// 2-hop onion routing — Phase 1 (Month 5).
///
/// # Module structure
/// ```text
/// onion/
///   packet.rs   — OnionPacket construction/parsing (pure crypto: X25519 + XChaCha20)
///   circuit.rs  — CircuitId, CircuitState, CircuitManager
///   router.rs   — OnionRelayHandler + InProcessRelay (Phase 1 in-process simulation)
///   executor.rs — LiveOnionDhtExecutor (ADR-002 production implementation)
/// ```
///
/// # Privacy guarantee (Phase 1 scope)
/// Phase 1 uses `InProcessRelay` — cryptographic correctness is verified but
/// no network-level anonymity is provided (relays are simulated in-process).
/// Real network anonymity is implemented in Phase 2 when packets are forwarded
/// to actual remote relay nodes via libp2p QUIC.
pub mod circuit;
pub mod executor;
pub mod packet;
pub mod router;
pub mod share;

pub use circuit::{CircuitManager, RelayInfo};
pub use executor::LiveOnionDhtExecutor;
pub use packet::{
    CircuitId, InnerPayload, OnionLayer, OnionLayerProcessor, OnionPacket, OnionPacketBuilder,
    ReturnPath, derive_onion_static_key,
};
pub use router::{ForwardCell, InProcessRelay, OnionRelayHandler, ResponseCell};
pub use share::{LiveOnionShareFetcher, OnionShareFetcher};
