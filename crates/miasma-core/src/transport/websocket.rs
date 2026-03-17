/// WebSocket-over-TLS transport — Phase 2 fallback (Task 14).
///
/// Wraps Miasma P2P traffic inside WebSocket frames over TLS.
/// From a DPI perspective this appears as ordinary WSS traffic to any host.
///
/// # How it works
/// 1. Establish a TCP+TLS connection to `addr` (standard port 443).
/// 2. Perform a WebSocket handshake with a path that looks like a CDN asset
///    (`/static/v2/bundle.js` by default — configurable).
/// 3. Tunnel raw Miasma protocol bytes as binary WebSocket frames.
///
/// # Phase 2 implementation note
/// The actual tokio-tungstenite integration is behind the `transport-ws`
/// feature flag so that it does not inflate the binary when unused.
/// The structs/traits below provide the interface regardless of feature flags.
use async_trait::async_trait;

use crate::MiasmaError;

use super::{PluggableTransport, TransportStream};

// ─── Configuration ────────────────────────────────────────────────────────────

/// Configuration for the WebSocket transport.
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// TLS SNI / Host header value.  Defaults to the target peer's domain/IP.
    pub sni_override: Option<String>,

    /// WebSocket path component — should look like a real CDN asset.
    pub ws_path: String,

    /// TLS port (default: 443).
    pub port: u16,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            sni_override: None,
            ws_path: "/static/v2/bundle.js".into(),
            port: 443,
        }
    }
}

// ─── Transport impl ───────────────────────────────────────────────────────────

pub struct WebSocketTransport {
    config: WebSocketConfig,
}

impl WebSocketTransport {
    pub fn new(config: WebSocketConfig) -> Self {
        Self { config }
    }
}

/// Placeholder byte stream for the WebSocket connection.
/// Phase 2 replaces this with a real `tokio-tungstenite` stream.
pub struct WsStream {
    _inner: Vec<u8>,
}

impl TransportStream for WsStream {
    fn as_bytes(&self) -> &[u8] {
        &self._inner
    }
}

#[async_trait]
impl PluggableTransport for WebSocketTransport {
    fn name(&self) -> &'static str {
        "websocket-over-tls"
    }

    async fn dial(&self, addr: &str) -> Result<Box<dyn TransportStream>, MiasmaError> {
        // Phase 2: integrate tokio-tungstenite here.
        // For now, return a stub so higher-level code can be tested against the trait.
        tracing::debug!(
            addr,
            path = self.config.ws_path,
            "WebSocket dial (stub — Phase 2)"
        );
        Err(MiasmaError::Sss("WebSocket transport not yet implemented (Phase 2)".into()))
    }

    async fn listen(&self, addr: &str) -> Result<(), MiasmaError> {
        tracing::debug!(addr, "WebSocket listen (stub — Phase 2)");
        Err(MiasmaError::Sss("WebSocket listen not yet implemented (Phase 2)".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_config_defaults() {
        let cfg = WebSocketConfig::default();
        assert_eq!(cfg.port, 443);
        assert!(cfg.ws_path.starts_with('/'));
    }

    #[test]
    fn websocket_transport_name() {
        let t = WebSocketTransport::new(WebSocketConfig::default());
        assert_eq!(t.name(), "websocket-over-tls");
    }
}
