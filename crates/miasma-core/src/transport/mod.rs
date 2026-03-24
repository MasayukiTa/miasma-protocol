/// Pluggable transport layer — Phase 2 (Task 14, ADR-001 extension).
///
/// The libp2p QUIC transport handles the happy path.  In censored
/// environments where raw QUIC is blocked by deep-packet inspection (DPI),
/// Miasma falls back to a `PluggableTransport` that wraps traffic in a form
/// that DPI cannot distinguish from ordinary HTTPS.
///
/// # Architecture (ADR-001 extension)
/// ```text
///           ┌──────────────────────────────────────┐
///           │           MiasmaNode (libp2p)         │
///           └──────────────┬───────────────────────┘
///                          │  chooses transport via TransportSelector
///          ┌───────────────┼─────────────────────────┐
///          ▼               ▼                         ▼
///   QuicTransport   WebSocketTransport   ObfuscatedQuicTransport
///   (ADR-001 default)  (fallback)          (REALITY-style camouflage)
/// ```
///
/// # Selection logic (Phase 2)
/// 1. Try QUIC.  If connection fails, fall back to the next transport in the
///    ordered list.
/// 2. `ObfuscatedQuicTransport` mimics HTTPS/CDN traffic via a shared TLS
///    fingerprint template — active probing returns an innocuous web page.
///
/// # Active probing resistance
/// `ObfuscatedQuicTransport` implements the REALITY-inspired design:
/// - The TLS ClientHello matches the fingerprint of a real browser.
/// - A shared secret (`probe_secret`) is required to distinguish Miasma
///   traffic from a real TLS handshake.  Without the secret, the server
///   proxies the connection to a legitimate CDN, defeating active probing.
pub mod diagnostics;
pub mod obfuscated;
pub mod payload;
pub mod proxy;
pub mod shadowsocks;
pub mod tor;
pub mod websocket;

use async_trait::async_trait;

use crate::MiasmaError;

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Abstraction over the wire transport used by Miasma.
///
/// The default transport is `libp2p-quic` (`QuicTransport`).  In censored
/// environments `WebSocketTransport` or `ObfuscatedQuicTransport` may be
/// selected instead.
#[async_trait]
pub trait PluggableTransport: Send + Sync {
    /// Human-readable transport name for logging/metrics.
    fn name(&self) -> &'static str;

    /// Dial a remote peer at `addr`, returning a raw byte stream handle.
    ///
    /// The returned `Box<dyn TransportStream>` abstracts over TCP, WebSocket,
    /// or QUIC streams so that higher-level code is transport-agnostic.
    async fn dial(&self, addr: &str) -> Result<Box<dyn TransportStream>, MiasmaError>;

    /// Listen for inbound connections on `addr`.
    async fn listen(&self, addr: &str) -> Result<(), MiasmaError>;
}

/// Abstraction over a bidirectional byte stream (TCP/WS/QUIC).
pub trait TransportStream: Send + Sync {
    fn as_bytes(&self) -> &[u8];
}

// ─── Selector ─────────────────────────────────────────────────────────────────

/// Ordered list of transports tried on each dial attempt.
///
/// Phase 2 default: `[QuicTransport, WebSocketTransport, ObfuscatedQuicTransport]`.
pub struct TransportSelector {
    transports: Vec<Box<dyn PluggableTransport>>,
}

impl TransportSelector {
    pub fn new(transports: Vec<Box<dyn PluggableTransport>>) -> Self {
        Self { transports }
    }

    /// Try each transport in order, returning the first successful connection.
    pub async fn dial(&self, addr: &str) -> Result<Box<dyn TransportStream>, MiasmaError> {
        let mut last_err = None;
        for t in &self.transports {
            match t.dial(addr).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    tracing::debug!("transport '{}' dial failed: {e}", t.name());
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or(MiasmaError::Sss("no transports available".into())))
    }
}
