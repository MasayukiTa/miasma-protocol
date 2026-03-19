/// WebSocket transport — real implementation using tokio-tungstenite.
///
/// # Architecture
/// ```text
///   Client (WssPayloadTransport)              Server (WssShareServer)
///   ─────────────────────────────              ────────────────────────
///   connect_async("ws://host:port/path")  →    TcpListener::bind(":0")
///   send(Binary: bincode(ShareFetchRequest))   accept → ws_stream
///   recv(Binary: bincode(ShareFetchResponse))  read → lookup → write
///   close                                      close
/// ```
///
/// # Wire format
/// Each WebSocket binary message contains a single bincode-encoded frame:
/// - Client → Server: `ShareFetchRequest` (38 bytes typical)
/// - Server → Client: `ShareFetchResponse` (variable, up to ~1 MiB)
///
/// # Phase 2.1 — TLS
/// For DPI resistance the connection should be WSS (WebSocket over TLS) on
/// port 443 with an innocuous SNI. The current implementation uses plain WS
/// for loopback tests. TLS wrapping is a separate concern (rustls integration).
use std::sync::Arc;

use futures::SinkExt;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

use crate::{
    network::node::{ShareFetchRequest, ShareFetchResponse},
    share::MiasmaShare,
    store::LocalShareStore,
    MiasmaError,
};

use super::payload::{PayloadTransport, PayloadTransportError, PayloadTransportKind, TransportPhase};

// ─── Configuration ────────────────────────────────────────────────────────────

/// Configuration for the WebSocket transport.
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// TLS SNI / Host header value.  Defaults to the target peer's domain/IP.
    pub sni_override: Option<String>,

    /// WebSocket path component — should look like a real CDN asset.
    pub ws_path: String,

    /// Listen/connect port (default: 443 for production, 0 for OS-assigned in tests).
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

// ─── WSS Share Server ────────────────────────────────────────────────────────

/// WebSocket server that serves share fetch requests from a `LocalShareStore`.
///
/// Runs as a tokio task alongside the daemon. Each incoming WebSocket
/// connection handles a single request-response cycle:
/// 1. Accept WebSocket upgrade
/// 2. Receive binary frame → deserialize `ShareFetchRequest`
/// 3. Look up share in `LocalShareStore`
/// 4. Send binary frame ← serialize `ShareFetchResponse`
/// 5. Close connection
pub struct WssShareServer {
    store: Arc<LocalShareStore>,
    listener: TcpListener,
    /// The port this server bound to (useful when port=0).
    pub port: u16,
}

impl WssShareServer {
    /// Bind a WebSocket share server to `127.0.0.1:{port}`.
    /// Use port=0 for OS-assigned port.
    pub async fn bind(store: Arc<LocalShareStore>, port: u16) -> Result<Self, MiasmaError> {
        let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .map_err(|e| MiasmaError::Network(format!("WSS bind failed: {e}")))?;
        let bound_port = listener
            .local_addr()
            .map_err(|e| MiasmaError::Network(format!("WSS local_addr: {e}")))?
            .port();
        info!("WSS share server bound on 127.0.0.1:{bound_port}");
        Ok(Self {
            store,
            listener,
            port: bound_port,
        })
    }

    /// Run the server loop. Accepts connections and handles each one.
    /// Call via `tokio::spawn(server.run())`.
    pub async fn run(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, addr)) => {
                    let store = self.store.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_wss_connection(stream, store).await {
                            debug!("WSS connection from {addr} error: {e}");
                        }
                    });
                }
                Err(e) => {
                    warn!("WSS accept error: {e}");
                }
            }
        }
    }
}

/// Handle a single WebSocket connection: read request, look up share, send response.
async fn handle_wss_connection(
    stream: tokio::net::TcpStream,
    store: Arc<LocalShareStore>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures::StreamExt;

    let ws_stream = tokio_tungstenite::accept_async(stream).await?;
    let (mut write, mut read) = ws_stream.split();

    // Read one binary message.
    let msg = match read.next().await {
        Some(Ok(Message::Binary(data))) => data,
        Some(Ok(Message::Close(_))) | None => return Ok(()),
        Some(Ok(other)) => {
            debug!("WSS: unexpected message type: {other:?}");
            return Ok(());
        }
        Some(Err(e)) => return Err(e.into()),
    };

    // Deserialize request.
    let request: ShareFetchRequest = match bincode::deserialize(&msg) {
        Ok(r) => r,
        Err(e) => {
            error!("WSS: failed to deserialize request: {e}");
            return Ok(());
        }
    };

    // Look up the share.
    let prefix: [u8; 8] = request.mid_digest[..8].try_into().unwrap();
    let candidates = store.search_by_mid_prefix(&prefix);
    let share: Option<MiasmaShare> = candidates.iter().find_map(|addr| {
        store.get(addr).ok().and_then(|s| {
            if s.slot_index == request.slot_index && s.segment_index == request.segment_index {
                Some(s)
            } else {
                None
            }
        })
    });

    // Serialize and send response.
    let response = ShareFetchResponse { share };
    let body = bincode::serialize(&response)?;
    write.send(Message::Binary(body)).await?;

    // Close.
    write.close().await.ok();
    Ok(())
}

// ─── WSS Payload Transport (client) ──────────────────────────────────────────

/// WebSocket payload transport — implements `PayloadTransport`.
///
/// Connects to a `WssShareServer` via WebSocket, sends a `ShareFetchRequest`,
/// and receives a `ShareFetchResponse`.
///
/// # Usage in fallback chain
/// ```text
/// PayloadTransportSelector:
///   1. DirectLibp2p → fails (QUIC blocked by DPI)
///   2. WssPayloadTransport → connects to ws://peer:port/path → success
/// ```
pub struct WssPayloadTransport {
    config: WebSocketConfig,
}

impl WssPayloadTransport {
    pub fn new(config: WebSocketConfig) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl PayloadTransport for WssPayloadTransport {
    fn kind(&self) -> PayloadTransportKind {
        PayloadTransportKind::WssTunnel
    }

    async fn fetch_share(
        &self,
        peer_addr: &str,
        mid_digest: [u8; 32],
        slot_index: u16,
        segment_index: u32,
    ) -> Result<Option<MiasmaShare>, PayloadTransportError> {
        use futures::StreamExt;

        // Build WebSocket URL. peer_addr is "host:port" or "host:port/path".
        let url = if peer_addr.contains("://") {
            peer_addr.to_string()
        } else {
            format!("ws://{}{}", peer_addr, self.config.ws_path)
        };

        // 1. Connect.
        let (ws_stream, _response) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| PayloadTransportError {
                phase: TransportPhase::Session,
                message: format!("WSS connect to {url}: {e}"),
            })?;

        let (mut write, mut read) = ws_stream.split();

        // 2. Send request.
        let request = ShareFetchRequest {
            mid_digest,
            slot_index,
            segment_index,
        };
        let body = bincode::serialize(&request).map_err(|e| PayloadTransportError {
            phase: TransportPhase::Data,
            message: format!("serialize request: {e}"),
        })?;
        write.send(Message::Binary(body)).await.map_err(|e| PayloadTransportError {
            phase: TransportPhase::Data,
            message: format!("send request: {e}"),
        })?;

        // 3. Receive response.
        let msg = match read.next().await {
            Some(Ok(Message::Binary(data))) => data,
            Some(Ok(Message::Close(_))) | None => {
                return Err(PayloadTransportError {
                    phase: TransportPhase::Data,
                    message: "connection closed before response".into(),
                });
            }
            Some(Ok(other)) => {
                return Err(PayloadTransportError {
                    phase: TransportPhase::Data,
                    message: format!("unexpected message type: {other:?}"),
                });
            }
            Some(Err(e)) => {
                return Err(PayloadTransportError {
                    phase: TransportPhase::Data,
                    message: format!("read response: {e}"),
                });
            }
        };

        // 4. Deserialize.
        let response: ShareFetchResponse =
            bincode::deserialize(&msg).map_err(|e| PayloadTransportError {
                phase: TransportPhase::Data,
                message: format!("deserialize response: {e}"),
            })?;

        Ok(response.share)
    }
}

// ─── Legacy PluggableTransport impl (kept for backward compat) ───────────────

use super::{PluggableTransport, TransportStream};
use async_trait::async_trait;

/// Legacy byte-stream transport wrapper.
/// For new code, use `WssPayloadTransport` which operates at the share level.
pub struct WebSocketTransport {
    config: WebSocketConfig,
}

impl WebSocketTransport {
    pub fn new(config: WebSocketConfig) -> Self {
        Self { config }
    }
}

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
        tracing::debug!(
            addr,
            path = self.config.ws_path,
            "WebSocket dial (use WssPayloadTransport for share-level fetch)"
        );
        Err(MiasmaError::Sss(
            "Use WssPayloadTransport for payload transport".into(),
        ))
    }

    async fn listen(&self, addr: &str) -> Result<(), MiasmaError> {
        tracing::debug!(addr, "WebSocket listen (use WssShareServer instead)");
        Err(MiasmaError::Sss(
            "Use WssShareServer for WebSocket listening".into(),
        ))
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{dissolve, DissolutionParams};

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

    #[tokio::test]
    async fn wss_server_client_share_roundtrip() {
        // 1. Dissolve content and store shares.
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalShareStore::open(dir.path(), 100).unwrap());
        let params = DissolutionParams::default();
        let (mid, shares) = dissolve(b"WSS roundtrip test payload", params).unwrap();
        for s in &shares {
            store.put(s).unwrap();
        }

        // 2. Start WSS server.
        let server = WssShareServer::bind(store, 0).await.unwrap();
        let port = server.port;
        tokio::spawn(server.run());

        // Brief delay for server to start accepting.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 3. Fetch a share via WSS client.
        let client = WssPayloadTransport::new(WebSocketConfig {
            port,
            ..Default::default()
        });
        let result = client
            .fetch_share(
                &format!("127.0.0.1:{port}"),
                *mid.as_bytes(),
                0, // slot 0
                0, // segment 0
            )
            .await;

        let share = result.expect("WSS fetch should succeed");
        assert!(share.is_some(), "share should exist for slot 0");
        let share = share.unwrap();
        assert_eq!(share.slot_index, 0);
        assert_eq!(share.segment_index, 0);
        assert_eq!(&share.mid_prefix, &mid.as_bytes()[..8]);
    }

    #[tokio::test]
    async fn wss_server_missing_share_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalShareStore::open(dir.path(), 100).unwrap());
        // Store is empty — no shares.

        let server = WssShareServer::bind(store, 0).await.unwrap();
        let port = server.port;
        tokio::spawn(server.run());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = WssPayloadTransport::new(WebSocketConfig::default());
        let result = client
            .fetch_share(&format!("127.0.0.1:{port}"), [0xAA; 32], 0, 0)
            .await;

        let share = result.expect("should not error on empty store");
        assert!(share.is_none(), "should be None for missing share");
    }

    #[tokio::test]
    async fn wss_connect_refused_is_session_error() {
        let client = WssPayloadTransport::new(WebSocketConfig::default());
        // Port 1 is almost certainly not listening.
        let result = client
            .fetch_share("127.0.0.1:1", [0; 32], 0, 0)
            .await;
        let err = result.unwrap_err();
        assert_eq!(err.phase, TransportPhase::Session);
        assert!(err.message.contains("WSS connect"));
    }

    #[tokio::test]
    async fn wss_multiple_shares_correct_slot_selection() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalShareStore::open(dir.path(), 100).unwrap());
        let params = DissolutionParams { data_shards: 3, total_shards: 5 };
        let (mid, shares) = dissolve(b"multi-slot WSS test", params).unwrap();
        for s in &shares {
            store.put(s).unwrap();
        }

        let server = WssShareServer::bind(store, 0).await.unwrap();
        let port = server.port;
        tokio::spawn(server.run());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = WssPayloadTransport::new(WebSocketConfig::default());

        // Fetch each slot and verify correct slot_index.
        for slot in 0..5u16 {
            let result = client
                .fetch_share(&format!("127.0.0.1:{port}"), *mid.as_bytes(), slot, 0)
                .await;
            let share = result
                .unwrap_or_else(|e| panic!("slot {slot} fetch failed: {e}"))
                .unwrap_or_else(|| panic!("slot {slot} not found"));
            assert_eq!(share.slot_index, slot, "wrong slot_index for slot {slot}");
        }
    }
}
