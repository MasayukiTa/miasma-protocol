/// WebSocket transport — real implementation using tokio-tungstenite.
///
/// # Architecture
/// ```text
///   Client (WssPayloadTransport)              Server (WssShareServer)
///   ─────────────────────────────              ────────────────────────
///   connect (optionally via SOCKS5 proxy) →    TcpListener::bind(":0")
///   TLS handshake (if tls_enabled)        →    TLS accept (if tls_acceptor present)
///   WS upgrade over stream                →    WS accept over stream
///   send(Binary: bincode(ShareFetchReq))       read → lookup → write
///   recv(Binary: bincode(ShareFetchResp))      close
///   close
/// ```
///
/// # Wire format
/// Each WebSocket binary message contains a single bincode-encoded frame:
/// - Client → Server: `ShareFetchRequest` (38 bytes typical)
/// - Server → Client: `ShareFetchResponse` (variable, up to ~1 MiB)
///
/// # TLS support
/// When `tls_enabled` is true, connections use rustls for TLS. The server
/// requires PEM cert/key via `bind_tls()`. The client uses webpki-roots
/// (Mozilla CA bundle) by default, or a custom CA if `custom_ca_pem` is set.
/// SNI can be overridden via `sni_override` for DPI resistance.
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

// ─── Proxy configuration ─────────────────────────────────────────────────────

/// SOCKS5 proxy configuration for tunneled connections.
///
/// Used by `WssPayloadTransport` to route WebSocket connections through a proxy
/// before performing the TLS handshake (if enabled). The proxy sees only the
/// encrypted TLS stream, providing an additional layer of metadata protection.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Proxy address in "host:port" form (e.g. "127.0.0.1:9050").
    pub addr: String,
    /// Proxy type — currently only SOCKS5 is implemented.
    pub kind: ProxyKind,
}

/// Supported proxy protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    /// SOCKS5 proxy (e.g. Tor, SSH -D).
    Socks5,
}

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

    /// Enable TLS wrapping (WSS). Default: false for backward compatibility.
    pub tls_enabled: bool,

    /// Server TLS certificate chain in PEM format.
    pub tls_cert_pem: Option<Vec<u8>>,

    /// Server TLS private key in PEM format.
    pub tls_key_pem: Option<Vec<u8>>,

    /// Custom CA certificate in PEM for client-side verification.
    /// If `None`, webpki-roots (Mozilla CA bundle) is used.
    pub custom_ca_pem: Option<Vec<u8>>,

    /// TCP connect timeout in milliseconds. Default: 10000.
    pub connect_timeout_ms: u64,

    /// Read timeout per WebSocket message in milliseconds. Default: 30000.
    pub read_timeout_ms: u64,

    /// Write timeout per WebSocket send in milliseconds. Default: 30000.
    pub write_timeout_ms: u64,

    /// Idle timeout for the entire connection in milliseconds. Default: 120000.
    pub idle_timeout_ms: u64,

    /// Maximum concurrent connections the server will accept. Default: 64.
    pub max_concurrent: usize,

    /// Maximum response body size in bytes. Default: 16 MiB.
    pub max_response_bytes: usize,

    /// Optional SOCKS5 proxy for outbound connections.
    pub proxy: Option<ProxyConfig>,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            sni_override: None,
            ws_path: "/static/v2/bundle.js".into(),
            port: 443,
            tls_enabled: false,
            tls_cert_pem: None,
            tls_key_pem: None,
            custom_ca_pem: None,
            connect_timeout_ms: 10_000,
            read_timeout_ms: 30_000,
            write_timeout_ms: 30_000,
            idle_timeout_ms: 120_000,
            max_concurrent: 64,
            max_response_bytes: 16 * 1024 * 1024,
            proxy: None,
        }
    }
}

// ─── WSS Share Server ────────────────────────────────────────────────────────

/// WebSocket server that serves share fetch requests from a `LocalShareStore`.
///
/// Runs as a tokio task alongside the daemon. Each incoming connection goes
/// through:
/// 1. TCP accept (with semaphore-based backpressure)
/// 2. Optional TLS handshake (if `bind_tls` was used)
/// 3. WebSocket upgrade
/// 4. Single request-response cycle (ShareFetchRequest → ShareFetchResponse)
/// 5. Close (releasing the semaphore permit)
pub struct WssShareServer {
    store: Arc<LocalShareStore>,
    listener: TcpListener,
    /// The port this server bound to (useful when port=0).
    pub port: u16,
    /// TLS acceptor — `None` for plain WS, `Some` for WSS.
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    /// Maximum concurrent connections.
    max_concurrent: usize,
    /// Idle timeout per connection.
    idle_timeout: std::time::Duration,
}

impl WssShareServer {
    /// Bind a plain (non-TLS) WebSocket share server to `127.0.0.1:{port}`.
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
            tls_acceptor: None,
            max_concurrent: 64,
            idle_timeout: std::time::Duration::from_millis(120_000),
        })
    }

    /// Bind a TLS-enabled WebSocket share server.
    ///
    /// `cert_pem` and `key_pem` are PEM-encoded certificate chain and private key.
    pub async fn bind_tls(
        store: Arc<LocalShareStore>,
        port: u16,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<Self, MiasmaError> {
        // Ensure the ring crypto provider is installed (idempotent).
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Parse certificate chain.
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &*cert_pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| MiasmaError::Network(format!("WSS TLS cert parse: {e}")))?;

        if certs.is_empty() {
            return Err(MiasmaError::Network(
                "WSS TLS: no certificates found in PEM".into(),
            ));
        }

        // Parse private key.
        let key = rustls_pemfile::private_key(&mut &*key_pem)
            .map_err(|e| MiasmaError::Network(format!("WSS TLS key parse: {e}")))?
            .ok_or_else(|| MiasmaError::Network("WSS TLS: no private key found in PEM".into()))?;

        // Build rustls ServerConfig.
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| MiasmaError::Network(format!("WSS TLS server config: {e}")))?;

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .map_err(|e| MiasmaError::Network(format!("WSS TLS bind failed: {e}")))?;
        let bound_port = listener
            .local_addr()
            .map_err(|e| MiasmaError::Network(format!("WSS TLS local_addr: {e}")))?
            .port();
        info!("WSS share server (TLS) bound on 127.0.0.1:{bound_port}");
        Ok(Self {
            store,
            listener,
            port: bound_port,
            tls_acceptor: Some(tls_acceptor),
            max_concurrent: 64,
            idle_timeout: std::time::Duration::from_millis(120_000),
        })
    }

    /// Set max concurrent connections (builder pattern).
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Set idle timeout (builder pattern).
    pub fn with_idle_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Run the server loop. Accepts connections and handles each one.
    /// Call via `tokio::spawn(server.run())`.
    pub async fn run(self) {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_concurrent));
        let tls_acceptor = self.tls_acceptor.clone();
        let idle_timeout = self.idle_timeout;

        loop {
            match self.listener.accept().await {
                Ok((tcp_stream, addr)) => {
                    let store = self.store.clone();
                    let sem = semaphore.clone();
                    let tls_acc = tls_acceptor.clone();

                    tokio::spawn(async move {
                        // Acquire backpressure permit.
                        let _permit = match sem.acquire().await {
                            Ok(p) => p,
                            Err(_) => {
                                debug!("WSS semaphore closed, dropping connection from {addr}");
                                return;
                            }
                        };

                        let result = tokio::time::timeout(idle_timeout, async {
                            if let Some(acceptor) = tls_acc {
                                // TLS path: handshake then WebSocket over TLS stream.
                                match acceptor.accept(tcp_stream).await {
                                    Ok(tls_stream) => {
                                        handle_wss_connection_tls(tls_stream, store).await
                                    }
                                    Err(e) => {
                                        debug!("WSS TLS handshake from {addr} failed: {e}");
                                        Ok(())
                                    }
                                }
                            } else {
                                // Plain WS path.
                                handle_wss_connection(tcp_stream, store).await
                            }
                        })
                        .await;

                        match result {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                debug!("WSS connection from {addr} error: {e}");
                            }
                            Err(_) => {
                                debug!("WSS connection from {addr} timed out (idle)");
                            }
                        }
                        // _permit dropped here, releasing the semaphore slot.
                    });
                }
                Err(e) => {
                    warn!("WSS accept error: {e}");
                }
            }
        }
    }
}

/// Handle a single plain WebSocket connection: read request, look up share, send response.
async fn handle_wss_connection(
    stream: tokio::net::TcpStream,
    store: Arc<LocalShareStore>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws_stream = tokio_tungstenite::accept_async(stream).await?;
    handle_ws_stream(ws_stream, store).await
}

/// Handle a single TLS WebSocket connection.
async fn handle_wss_connection_tls(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    store: Arc<LocalShareStore>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws_stream = tokio_tungstenite::accept_async(stream).await?;
    handle_ws_stream(ws_stream, store).await
}

/// Common WebSocket handler logic for both plain and TLS streams.
async fn handle_ws_stream<S>(
    ws_stream: tokio_tungstenite::WebSocketStream<S>,
    store: Arc<LocalShareStore>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures::StreamExt;

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
    let prefix: [u8; 8] = match request.mid_digest[..8].try_into() {
        Ok(p) => p,
        Err(_) => {
            error!("WSS: invalid mid_digest length in request");
            return Ok(());
        }
    };
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
/// Connects to a `WssShareServer` via WebSocket (plain or TLS), sends a
/// `ShareFetchRequest`, and receives a `ShareFetchResponse`.
///
/// # Features
/// - **TLS**: When `config.tls_enabled`, wraps the TCP stream in rustls TLS
///   with configurable SNI override and custom CA support.
/// - **Timeouts**: Connect, read, and write operations are individually bounded.
/// - **Backpressure**: Response size is checked against `max_response_bytes`.
/// - **Proxy**: When `config.proxy` is set, connects via SOCKS5 proxy.
///
/// # Usage in fallback chain
/// ```text
/// PayloadTransportSelector:
///   1. DirectLibp2p → fails (QUIC blocked by DPI)
///   2. WssPayloadTransport → connects to wss://peer:port/path → success
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
        // Parse host:port from peer_addr.
        let (host, port) = parse_host_port(peer_addr, self.config.port);
        let connect_timeout = std::time::Duration::from_millis(self.config.connect_timeout_ms);
        let read_timeout = std::time::Duration::from_millis(self.config.read_timeout_ms);
        let write_timeout = std::time::Duration::from_millis(self.config.write_timeout_ms);

        // Build WebSocket URL.
        let scheme = if self.config.tls_enabled { "wss" } else { "ws" };
        let url = if peer_addr.contains("://") {
            peer_addr.to_string()
        } else {
            format!("{scheme}://{host}:{port}{}", self.config.ws_path)
        };

        // 1. Establish TCP connection (optionally through proxy).
        let tcp_stream = if let Some(ref proxy) = self.config.proxy {
            // SOCKS5 proxy path.
            let proxy_stream = tokio::time::timeout(
                connect_timeout,
                tokio_socks::tcp::Socks5Stream::connect(&*proxy.addr, (host.as_str(), port)),
            )
            .await
            .map_err(|_| PayloadTransportError {
                phase: TransportPhase::Session,
                message: format!("WSS proxy connect timeout to {}", proxy.addr),
            })?
            .map_err(|e| PayloadTransportError {
                phase: TransportPhase::Session,
                message: format!("WSS SOCKS5 connect via {}: {e}", proxy.addr),
            })?;
            proxy_stream.into_inner()
        } else {
            // Direct TCP connection.
            let addr_str = format!("{host}:{port}");
            tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(&addr_str))
                .await
                .map_err(|_| PayloadTransportError {
                    phase: TransportPhase::Session,
                    message: format!("WSS connect timeout to {addr_str}"),
                })?
                .map_err(|e| PayloadTransportError {
                    phase: TransportPhase::Session,
                    message: format!("WSS connect to {addr_str}: {e}"),
                })?
        };

        // 2. Optionally wrap in TLS.
        if self.config.tls_enabled {
            let tls_connector = build_client_tls_connector(&self.config)?;
            let sni = self
                .config
                .sni_override
                .as_deref()
                .unwrap_or(&host);
            let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
                .map_err(|e| PayloadTransportError {
                    phase: TransportPhase::Session,
                    message: format!("WSS TLS invalid SNI '{sni}': {e}"),
                })?;
            let tls_stream = tls_connector
                .connect(server_name, tcp_stream)
                .await
                .map_err(|e| PayloadTransportError {
                    phase: TransportPhase::Session,
                    message: format!("WSS TLS handshake: {e}"),
                })?;

            // WebSocket upgrade over TLS stream.
            let ws_upgrade_timeout = std::cmp::min(connect_timeout, read_timeout);
            let ws_result = tokio::select! {
                res = tokio_tungstenite::client_async(&url, tls_stream) => {
                    res.map_err(|e| PayloadTransportError {
                        phase: TransportPhase::Session,
                        message: format!("WSS upgrade over TLS to {url}: {e}"),
                    })
                }
                _ = tokio::time::sleep(ws_upgrade_timeout) => {
                    Err(PayloadTransportError {
                        phase: TransportPhase::Session,
                        message: format!("WSS upgrade timeout to {url}"),
                    })
                }
            };
            let (ws_stream, _response) = ws_result?;

            wss_request_response(ws_stream, mid_digest, slot_index, segment_index, read_timeout, write_timeout, self.config.max_response_bytes).await
        } else {
            // Plain WebSocket upgrade over TCP.
            // Use read_timeout for the WS handshake — TCP connect already
            // succeeded, so the wait is for the server's HTTP upgrade response.
            // We use select! instead of timeout() because client_async may not
            // be cancel-safe with timeout() on all platforms.
            let ws_upgrade_timeout = std::cmp::min(connect_timeout, read_timeout);
            let ws_result = tokio::select! {
                res = tokio_tungstenite::client_async(&url, tcp_stream) => {
                    res.map_err(|e| PayloadTransportError {
                        phase: TransportPhase::Session,
                        message: format!("WSS connect to {url}: {e}"),
                    })
                }
                _ = tokio::time::sleep(ws_upgrade_timeout) => {
                    Err(PayloadTransportError {
                        phase: TransportPhase::Session,
                        message: format!("WSS upgrade timeout to {url}"),
                    })
                }
            };
            let (ws_stream, _response) = ws_result?;

            wss_request_response(ws_stream, mid_digest, slot_index, segment_index, read_timeout, write_timeout, self.config.max_response_bytes).await
        }
    }
}

/// Build a rustls `TlsConnector` for the client side.
fn build_client_tls_connector(
    config: &WebSocketConfig,
) -> Result<tokio_rustls::TlsConnector, PayloadTransportError> {
    // Ensure the ring crypto provider is installed (idempotent).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let root_store = if let Some(ref ca_pem) = config.custom_ca_pem {
        // Custom CA.
        let mut store = rustls::RootCertStore::empty();
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &**ca_pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| PayloadTransportError {
                    phase: TransportPhase::Session,
                    message: format!("WSS TLS custom CA parse: {e}"),
                })?;
        for cert in certs {
            store.add(cert).map_err(|e| PayloadTransportError {
                phase: TransportPhase::Session,
                message: format!("WSS TLS add custom CA: {e}"),
            })?;
        }
        store
    } else {
        // Mozilla CA bundle via webpki-roots.
        let mut store = rustls::RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        store
    };

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(tokio_rustls::TlsConnector::from(Arc::new(client_config)))
}

/// Perform the WebSocket request-response cycle over any stream type.
async fn wss_request_response<S>(
    ws_stream: tokio_tungstenite::WebSocketStream<S>,
    mid_digest: [u8; 32],
    slot_index: u16,
    segment_index: u32,
    read_timeout: std::time::Duration,
    write_timeout: std::time::Duration,
    max_response_bytes: usize,
) -> Result<Option<MiasmaShare>, PayloadTransportError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures::StreamExt;

    let (mut write, mut read) = ws_stream.split();

    // Send request with write timeout.
    let request = ShareFetchRequest {
        mid_digest,
        slot_index,
        segment_index,
    };
    let body = bincode::serialize(&request).map_err(|e| PayloadTransportError {
        phase: TransportPhase::Data,
        message: format!("serialize request: {e}"),
    })?;

    tokio::time::timeout(write_timeout, write.send(Message::Binary(body)))
        .await
        .map_err(|_| PayloadTransportError {
            phase: TransportPhase::Data,
            message: "WSS write timeout".into(),
        })?
        .map_err(|e| PayloadTransportError {
            phase: TransportPhase::Data,
            message: format!("send request: {e}"),
        })?;

    // Receive response with read timeout.
    let msg = tokio::time::timeout(read_timeout, read.next())
        .await
        .map_err(|_| PayloadTransportError {
            phase: TransportPhase::Data,
            message: "WSS read timeout".into(),
        })?;

    let data = match msg {
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

    // Check response size against limit.
    if data.len() > max_response_bytes {
        return Err(PayloadTransportError {
            phase: TransportPhase::Data,
            message: format!(
                "response too large: {} bytes (max {})",
                data.len(),
                max_response_bytes
            ),
        });
    }

    // Deserialize.
    let response: ShareFetchResponse =
        bincode::deserialize(&data).map_err(|e| PayloadTransportError {
            phase: TransportPhase::Data,
            message: format!("deserialize response: {e}"),
        })?;

    Ok(response.share)
}

/// Parse "host:port" from a peer address string.
/// Falls back to `default_port` if no port is present.
fn parse_host_port(addr: &str, default_port: u16) -> (String, u16) {
    // Strip any scheme prefix.
    let stripped = addr
        .strip_prefix("ws://")
        .or_else(|| addr.strip_prefix("wss://"))
        .unwrap_or(addr);

    // Strip path.
    let host_port = stripped.split('/').next().unwrap_or(stripped);

    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_string(), port);
        }
    }
    (host_port.to_string(), default_port)
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

    // ─── New tests ────────────────────────────────────────────────────────────

    #[test]
    fn wss_config_tls_defaults() {
        let cfg = WebSocketConfig::default();
        // TLS disabled by default for backward compatibility.
        assert!(!cfg.tls_enabled);
        assert!(cfg.tls_cert_pem.is_none());
        assert!(cfg.tls_key_pem.is_none());
        assert!(cfg.custom_ca_pem.is_none());
        // Timeouts are positive and sensible.
        assert_eq!(cfg.connect_timeout_ms, 10_000);
        assert_eq!(cfg.read_timeout_ms, 30_000);
        assert_eq!(cfg.write_timeout_ms, 30_000);
        assert_eq!(cfg.idle_timeout_ms, 120_000);
        // Backpressure defaults.
        assert_eq!(cfg.max_concurrent, 64);
        assert_eq!(cfg.max_response_bytes, 16 * 1024 * 1024);
        // No proxy by default.
        assert!(cfg.proxy.is_none());
    }

    #[tokio::test]
    async fn wss_connect_timeout_fires() {
        // Start a TCP listener that accepts but never sends any data.
        // This causes the WebSocket handshake to hang indefinitely.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn a task that accepts connections and holds them open.
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                // Hold the stream open without reading/writing.
                tokio::spawn(async move {
                    let _keep = stream;
                    tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                });
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let client = WssPayloadTransport::new(WebSocketConfig {
            port,
            // Very short read timeout — the WS handshake will be waiting for
            // the server to respond, which should trigger a timeout in fetch.
            // connect_timeout won't fire because TCP connect succeeds.
            // The hang happens during WS upgrade (client_async), which reads
            // from the stream. We set read_timeout short.
            connect_timeout_ms: 100,
            read_timeout_ms: 100,
            write_timeout_ms: 100,
            ..Default::default()
        });

        let start = std::time::Instant::now();
        let result = client
            .fetch_share(&format!("127.0.0.1:{port}"), [0; 32], 0, 0)
            .await;
        let elapsed = start.elapsed();

        // Should fail (either connect timeout or session error from WS handshake timeout).
        assert!(result.is_err(), "should timeout/error");
        let err = result.unwrap_err();
        assert_eq!(err.phase, TransportPhase::Session);
        // Should complete in a reasonable time (well under 5s).
        assert!(
            elapsed.as_millis() < 5_000,
            "should not hang; elapsed: {elapsed:?}"
        );
    }

    #[test]
    fn parse_host_port_basic() {
        assert_eq!(parse_host_port("1.2.3.4:8080", 443), ("1.2.3.4".into(), 8080));
        assert_eq!(parse_host_port("host.example.com", 443), ("host.example.com".into(), 443));
        assert_eq!(
            parse_host_port("ws://127.0.0.1:9999/path", 443),
            ("127.0.0.1".into(), 9999)
        );
    }
}
