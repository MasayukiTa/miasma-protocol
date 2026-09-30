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
/// # Wire format (version 1)
/// Each WebSocket binary message is `[WS_WIRE_VERSION] ++ bincode(message)`:
/// - Client → Server: [`WsRequest`], either `Share(ShareFetchRequest)` or
///   `Record { mid_digest }` (a few dozen bytes).
/// - Server → Client: the matching [`WsResponse`]: a share (up to
///   `SHARE_MSG_MAX`, 8 MiB) or the record value with its manifest trailer
///   (at most [`WS_RECORD_MAX_BYTES`]).
///
/// A connection carries many request/response pairs, strictly one at a time and
/// in order, up to [`WS_MAX_REQUESTS_PER_CONNECTION`]; the server then closes it
/// and the client dials again. Beta software: this replaces the earlier
/// unversioned single-request format; both ends must be the same build family.
///
/// # TLS support
/// When `tls_enabled` is true, connections use rustls for TLS. The server
/// requires PEM cert/key via `bind_tls()`. The client uses webpki-roots
/// (Mozilla CA bundle) by default, or a custom CA if `custom_ca_pem` is set.
/// SNI can be overridden via `sni_override` for DPI resistance.
use std::{fmt, sync::Arc, time::Duration};

use bincode::Options as _;
use futures::SinkExt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::{protocol::WebSocketConfig as WsProtocolConfig, Message};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::{
    network::node::{ShareFetchRequest, ShareFetchResponse},
    share::MiasmaShare,
    store::LocalShareStore,
    MiasmaError,
};

use super::payload::{
    PayloadTransport, PayloadTransportError, PayloadTransportKind, TransportPhase,
};

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
#[derive(Clone)]
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
    pub tls_key_pem: Option<Zeroizing<Vec<u8>>>,

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

    /// Skip TLS certificate verification entirely.
    ///
    /// **Security**: disables all server authentication. Use only for
    /// connectivity testing through MITM proxies (e.g. corporate TLS
    /// inspection). Never set this in production.
    pub accept_invalid_certs: bool,
}

impl fmt::Debug for WebSocketConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocketConfig")
            .field("sni_override", &self.sni_override)
            .field("ws_path", &self.ws_path)
            .field("port", &self.port)
            .field("tls_enabled", &self.tls_enabled)
            .field(
                "tls_cert_pem_len",
                &self.tls_cert_pem.as_ref().map(Vec::len),
            )
            .field("tls_key_pem_configured", &self.tls_key_pem.is_some())
            .field(
                "custom_ca_pem_len",
                &self.custom_ca_pem.as_ref().map(Vec::len),
            )
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("read_timeout_ms", &self.read_timeout_ms)
            .field("write_timeout_ms", &self.write_timeout_ms)
            .field("idle_timeout_ms", &self.idle_timeout_ms)
            .field("max_concurrent", &self.max_concurrent)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("proxy", &self.proxy)
            .field("accept_invalid_certs", &self.accept_invalid_certs)
            .finish()
    }
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
            accept_invalid_certs: false,
        }
    }
}

// ─── Wire protocol ───────────────────────────────────────────────────────────

/// First byte of every message. A peer that sends anything else is dropped.
pub const WS_WIRE_VERSION: u8 = 1;

/// Largest request the server reads. A request is a few dozen bytes; this is
/// also the WebSocket frame/message limit it enforces on inbound frames, so a
/// peer that declares a bigger frame is refused before any of it is buffered.
pub const WS_REQUEST_MAX_BYTES: usize = 1024;

/// Largest record value (record + manifest trailer) the server will send. The
/// same bound the DHT applies when a record is published, so anything that can
/// be published can be served; the manifest alone is at most 8 MiB.
pub const WS_RECORD_MAX_BYTES: usize = 16 * 1024 * 1024 - 64 * 1024;

/// Largest message a client accepts (frame and message limit). Above a share
/// (8 MiB) and a record ([`WS_RECORD_MAX_BYTES`]), below the 64 MiB library default.
pub const WS_MAX_MESSAGE_BYTES: usize = 17 * 1024 * 1024;

/// Requests served on one connection before the server closes it.
pub const WS_MAX_REQUESTS_PER_CONNECTION: usize = 512;

/// Ping/pong frames tolerated per connection (they do not count as requests, but
/// they must not keep a connection alive for ever either).
const WS_MAX_CONTROL_FRAMES: usize = 64;

/// What a client may ask of a Miasma WebSocket endpoint. There is deliberately
/// nothing else: no control operation, no listing, no store or daemon access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WsRequest {
    /// One share, by (MID, segment, slot).
    Share(ShareFetchRequest),
    /// The record and manifest for a MID, as the DHT would hold them.
    Record { mid_digest: [u8; 32] },
}

/// The answer to one [`WsRequest`], in the same variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WsResponse {
    Share(ShareFetchResponse),
    /// `None` for an unknown MID; no detail is given.
    Record {
        value: Option<Vec<u8>>,
    },
}

/// Bincode configuration for the wire: fixed-width integers, no trailing bytes,
/// and a size limit so a declared length can never size an allocation past it.
fn wire_codec(limit: usize) -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(limit as u64)
}

/// `[WS_WIRE_VERSION] ++ bincode(message)`.
pub fn encode_ws_message<T: Serialize>(message: &T) -> Result<Vec<u8>, String> {
    let body = wire_codec(WS_MAX_MESSAGE_BYTES)
        .serialize(message)
        .map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(WS_WIRE_VERSION);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode a message of at most `limit` bytes. Any deviation (wrong version,
/// trailing bytes, unknown variant, over-long declared length) is an error.
pub fn decode_ws_message<T: DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T, String> {
    match bytes.split_first() {
        Some((&WS_WIRE_VERSION, body)) if bytes.len() <= limit => wire_codec(limit)
            .deserialize(body)
            .map_err(|e| e.to_string()),
        Some((&WS_WIRE_VERSION, _)) => Err("message too large".into()),
        Some(_) => Err("unsupported wire version".into()),
        None => Err("empty message".into()),
    }
}

/// WebSocket frame/message limits for one side.
pub(crate) fn ws_limits(max: usize) -> WsProtocolConfig {
    WsProtocolConfig {
        max_message_size: Some(max),
        max_frame_size: Some(max),
        ..Default::default()
    }
}

/// Where the server gets a MID's record from. The daemon implements this over
/// its own DHT store, so an endpoint can answer `Record` for what it published.
#[async_trait::async_trait]
pub trait RecordProvider: Send + Sync {
    /// The signed record envelope (signature and signer included; the value is
    /// the record plus its manifest trailer) held locally for the MID. The
    /// receiver opens it with `transfer::open_signed_record`, so it can check who
    /// signed it.
    async fn record_value(&self, mid_digest: [u8; 32]) -> Option<Vec<u8>>;
}

#[async_trait::async_trait]
impl RecordProvider for crate::network::node::DhtHandle {
    async fn record_value(&self, mid_digest: [u8; 32]) -> Option<Vec<u8>> {
        self.local_record_value(mid_digest).await
    }
}

// ─── WSS Share Server ────────────────────────────────────────────────────────

/// WebSocket server that serves share and record requests from a
/// `LocalShareStore` and a [`RecordProvider`].
///
/// Runs as a tokio task alongside the daemon. Each incoming connection goes
/// through:
/// 1. TCP accept; over the concurrency cap the connection is closed at once
///    (nothing is queued, so a flood cannot pile up tasks or sockets)
/// 2. Optional TLS handshake (if `bind_tls` was used), time-limited
/// 3. WebSocket upgrade, time-limited, with request-sized frame limits
/// 4. Up to `max_requests` request/response cycles, each read time-limited
/// 5. Close (releasing the semaphore permit)
///
/// It serves only [`WsRequest`]. It holds no reference to the daemon's control
/// channel, token or IPC, so nothing that arrives here can reach them.
pub struct WssShareServer {
    store: Arc<LocalShareStore>,
    records: Option<Arc<dyn RecordProvider>>,
    listener: TcpListener,
    /// The port this server bound to (useful when port=0).
    pub port: u16,
    /// TLS acceptor — `None` for plain WS, `Some` for WSS.
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    /// Maximum concurrent connections.
    max_concurrent: usize,
    /// How long the server waits for the next message (or the handshake).
    idle_timeout: Duration,
    /// How long one response may take to be written.
    write_timeout: Duration,
    /// Requests served per connection.
    max_requests: usize,
}

/// What one connection handler needs; cheap to clone per connection.
#[derive(Clone)]
struct ServeCtx {
    store: Arc<LocalShareStore>,
    records: Option<Arc<dyn RecordProvider>>,
    idle_timeout: Duration,
    write_timeout: Duration,
    max_requests: usize,
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
            records: None,
            listener,
            port: bound_port,
            tls_acceptor: None,
            max_concurrent: 64,
            idle_timeout: Duration::from_millis(120_000),
            write_timeout: Duration::from_millis(60_000),
            max_requests: WS_MAX_REQUESTS_PER_CONNECTION,
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
            records: None,
            listener,
            port: bound_port,
            tls_acceptor: Some(tls_acceptor),
            max_concurrent: 64,
            idle_timeout: Duration::from_millis(120_000),
            write_timeout: Duration::from_millis(60_000),
            max_requests: WS_MAX_REQUESTS_PER_CONNECTION,
        })
    }

    /// Set max concurrent connections (builder pattern).
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Set idle timeout (builder pattern).
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the number of requests served per connection (builder pattern).
    pub fn with_max_requests_per_connection(mut self, max: usize) -> Self {
        self.max_requests = max.max(1);
        self
    }

    /// Let this endpoint answer [`WsRequest::Record`] from `records`. Without a
    /// provider every record request is answered "unknown".
    pub fn with_record_provider(mut self, records: Arc<dyn RecordProvider>) -> Self {
        self.records = Some(records);
        self
    }

    /// Run the server loop. Accepts connections and handles each one.
    /// Call via `tokio::spawn(server.run())`.
    pub async fn run(self) {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_concurrent));
        let tls_acceptor = self.tls_acceptor.clone();
        let ctx = ServeCtx {
            store: self.store.clone(),
            records: self.records.clone(),
            idle_timeout: self.idle_timeout,
            write_timeout: self.write_timeout,
            max_requests: self.max_requests,
        };
        let mut connections = tokio::task::JoinSet::new();

        loop {
            while let Some(result) = connections.try_join_next() {
                if let Err(e) = result {
                    debug!("WSS connection task join error: {e}");
                }
            }
            match self.listener.accept().await {
                Ok((tcp_stream, addr)) => {
                    // Over the cap: close now. Nothing waits for a slot, so a
                    // flood of connections holds no task and no buffer.
                    let permit = match semaphore.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            debug!("WSS at capacity, dropping connection from {addr}");
                            drop(tcp_stream);
                            continue;
                        }
                    };
                    let ctx = ctx.clone();
                    let tls_acc = tls_acceptor.clone();

                    connections.spawn(async move {
                        let _permit = permit;
                        let result = if let Some(acceptor) = tls_acc {
                            // TLS path: handshake (time-limited), then WebSocket over TLS.
                            match tokio::time::timeout(
                                ctx.idle_timeout,
                                acceptor.accept(tcp_stream),
                            )
                            .await
                            {
                                Ok(Ok(tls_stream)) => serve_connection(tls_stream, &ctx).await,
                                Ok(Err(e)) => {
                                    debug!("WSS TLS handshake from {addr} failed: {e}");
                                    Ok(())
                                }
                                Err(_) => {
                                    debug!("WSS TLS handshake from {addr} timed out");
                                    Ok(())
                                }
                            }
                        } else {
                            serve_connection(tcp_stream, &ctx).await
                        };
                        if let Err(e) = result {
                            debug!("WSS connection from {addr} ended: {e}");
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

type ServeResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Upgrade one accepted stream and serve it. The upgrade is time-limited and the
/// frame limits are request-sized from the first byte after the upgrade.
async fn serve_connection<S>(stream: S, ctx: &ServeCtx) -> ServeResult
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let ws_stream = tokio::time::timeout(
        ctx.idle_timeout,
        tokio_tungstenite::accept_async_with_config(stream, Some(ws_limits(WS_REQUEST_MAX_BYTES))),
    )
    .await
    .map_err(|_| "WebSocket upgrade timed out")??;
    handle_ws_stream(ws_stream, ctx).await
}

/// Answer one request. Never fails and never says why it has nothing: an unknown
/// MID, a missing share and a record over the size cap all look the same.
async fn answer_request(request: WsRequest, ctx: &ServeCtx) -> WsResponse {
    match request {
        WsRequest::Share(request) => {
            let store = ctx.store.clone();
            // Found through the store's index (no decryption), then exactly one
            // decryption: the cost of a request must not grow with the number of
            // shares stored. Store reads decrypt, so they stay off the async threads.
            let share = tokio::task::spawn_blocking(move || {
                let prefix: [u8; 8] = request.mid_digest[..8].try_into().ok()?;
                let addr = store.find_piece(&prefix, request.segment_index, request.slot_index)?;
                store.get_untouched(&addr).ok().filter(|s| {
                    s.mid_prefix == prefix
                        && s.slot_index == request.slot_index
                        && s.segment_index == request.segment_index
                })
            })
            .await
            .ok()
            .flatten();
            WsResponse::Share(ShareFetchResponse { share })
        }
        WsRequest::Record { mid_digest } => {
            let value = match &ctx.records {
                Some(records) => records
                    .record_value(mid_digest)
                    .await
                    .filter(|v| v.len() <= WS_RECORD_MAX_BYTES),
                None => None,
            };
            WsResponse::Record { value }
        }
    }
}

/// The request loop for one upgraded connection, plain or TLS.
async fn handle_ws_stream<S>(
    ws_stream: tokio_tungstenite::WebSocketStream<S>,
    ctx: &ServeCtx,
) -> ServeResult
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures::StreamExt;

    let (mut write, mut read) = ws_stream.split();
    let mut served = 0usize;
    let mut control_frames = 0usize;

    while served < ctx.max_requests {
        let msg = match tokio::time::timeout(ctx.idle_timeout, read.next()).await {
            // Idle: the client is gone or has nothing more to ask.
            Err(_) => return Ok(()),
            Ok(None) | Ok(Some(Ok(Message::Close(_)))) => return Ok(()),
            Ok(Some(Ok(Message::Binary(data)))) => data,
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {
                control_frames += 1;
                if control_frames > WS_MAX_CONTROL_FRAMES {
                    return Ok(());
                }
                continue;
            }
            // Text or a raw frame: not this protocol. Close without a word.
            Ok(Some(Ok(_))) => return Ok(()),
            Ok(Some(Err(e))) => return Err(e.into()),
        };

        // A request that does not parse ends the connection; nothing about it
        // (not even that it was malformed) is echoed back.
        let request: WsRequest = match decode_ws_message(&msg, WS_REQUEST_MAX_BYTES) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        served += 1;

        let response = answer_request(request, ctx).await;
        let body = encode_ws_message(&response)?;
        tokio::time::timeout(ctx.write_timeout, write.send(Message::Binary(body)))
            .await
            .map_err(|_| "response write timed out")??;
    }

    // Per-connection request limit reached: the client dials again.
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
/// - **Proxy**: Supports authenticated SOCKS5 and HTTP CONNECT at runtime.
///   `config.proxy` remains the legacy unauthenticated SOCKS5 path.
///
/// # Usage in fallback chain
/// ```text
/// PayloadTransportSelector:
///   1. DirectLibp2p → fails (QUIC blocked by DPI)
///   2. WssPayloadTransport → connects to wss://peer:port/path → success
/// ```
pub struct WssPayloadTransport {
    config: WebSocketConfig,
    runtime_proxy: Option<super::proxy::ProxyConfig>,
}

impl WssPayloadTransport {
    pub fn new(config: WebSocketConfig) -> Self {
        Self {
            config,
            runtime_proxy: None,
        }
    }

    /// Construct a WSS transport with the credential-aware runtime proxy.
    ///
    /// `WebSocketConfig::proxy` is retained for API compatibility with the
    /// original unauthenticated SOCKS5 path. Daemon configuration uses this
    /// runtime form so SOCKS5 authentication and HTTP CONNECT work as declared.
    pub fn new_with_runtime_proxy(
        config: WebSocketConfig,
        runtime_proxy: Option<super::proxy::ProxyConfig>,
    ) -> Self {
        Self {
            config,
            runtime_proxy,
        }
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

        // 1. Establish TCP connection (optionally through proxy). The daemon
        // uses `runtime_proxy`, which supports SOCKS5 credentials and HTTP CONNECT.
        // `config.proxy` remains as the legacy unauthenticated SOCKS5 API.
        let tcp_stream = if let Some(ref proxy) = self.runtime_proxy {
            tokio::time::timeout(connect_timeout, proxy.connect(host.as_str(), port))
                .await
                .map_err(|_| PayloadTransportError {
                    phase: TransportPhase::Session,
                    message: format!("WSS {} proxy connect timeout", proxy.display_name()),
                })?
                .map_err(|e| PayloadTransportError {
                    phase: TransportPhase::Session,
                    message: format!("WSS {} proxy connect: {e}", proxy.display_name()),
                })?
        } else if let Some(ref proxy) = self.config.proxy {
            // Legacy unauthenticated SOCKS5 proxy path.
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
            let sni = self.config.sni_override.as_deref().unwrap_or(&host);
            let server_name =
                rustls::pki_types::ServerName::try_from(sni.to_string()).map_err(|e| {
                    PayloadTransportError {
                        phase: TransportPhase::Session,
                        message: format!("WSS TLS invalid SNI '{sni}': {e}"),
                    }
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
                res = tokio_tungstenite::client_async_with_config(&url, tls_stream, Some(ws_limits(WS_MAX_MESSAGE_BYTES))) => {
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

            wss_request_response(
                ws_stream,
                mid_digest,
                slot_index,
                segment_index,
                read_timeout,
                write_timeout,
                self.config.max_response_bytes,
            )
            .await
        } else {
            // Plain WebSocket upgrade over TCP.
            // Use read_timeout for the WS handshake — TCP connect already
            // succeeded, so the wait is for the server's HTTP upgrade response.
            // We use select! instead of timeout() because client_async may not
            // be cancel-safe with timeout() on all platforms.
            let ws_upgrade_timeout = std::cmp::min(connect_timeout, read_timeout);
            let ws_result = tokio::select! {
                res = tokio_tungstenite::client_async_with_config(&url, tcp_stream, Some(ws_limits(WS_MAX_MESSAGE_BYTES))) => {
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

            wss_request_response(
                ws_stream,
                mid_digest,
                slot_index,
                segment_index,
                read_timeout,
                write_timeout,
                self.config.max_response_bytes,
            )
            .await
        }
    }
}

/// A TLS certificate verifier that accepts any certificate (for testing only).
#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

/// Build a rustls `TlsConnector` for the client side.
fn build_client_tls_connector(
    config: &WebSocketConfig,
) -> Result<tokio_rustls::TlsConnector, PayloadTransportError> {
    // Ensure the ring crypto provider is installed (idempotent).
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Testing mode: accept any certificate (for MITM proxy environments).
    if config.accept_invalid_certs {
        let tls_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| PayloadTransportError {
            phase: TransportPhase::Session,
            message: format!("TLS protocol versions: {e}"),
        })?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
        return Ok(tokio_rustls::TlsConnector::from(Arc::new(tls_cfg)));
    }

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
///
/// Exposed as `pub(crate)` so that Shadowsocks and Tor transports can
/// reuse the same WSS protocol over their proxied streams.
pub(crate) async fn wss_request_response<S>(
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
    let request = WsRequest::Share(ShareFetchRequest {
        mid_digest,
        slot_index,
        segment_index,
    });
    let body = encode_ws_message(&request).map_err(|e| PayloadTransportError {
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
    let response: WsResponse =
        decode_ws_message(&data, max_response_bytes).map_err(|e| PayloadTransportError {
            phase: TransportPhase::Data,
            message: format!("deserialize response: {e}"),
        })?;

    match response {
        WsResponse::Share(r) => Ok(r.share),
        WsResponse::Record { .. } => Err(PayloadTransportError {
            phase: TransportPhase::Data,
            message: "deserialize response: a record answered a share request".into(),
        }),
    }
}

/// Parse "host:port" from a peer address string.
/// Falls back to `default_port` if no port is present.
pub(crate) fn parse_host_port(addr: &str, default_port: u16) -> (String, u16) {
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

    #[test]
    fn websocket_config_debug_redacts_tls_key() {
        let cfg = WebSocketConfig {
            tls_key_pem: Some(Zeroizing::new(b"debug-tls-key-value".to_vec())),
            ..Default::default()
        };
        let key_debug = format!("{:?}", cfg.tls_key_pem.as_ref().unwrap());
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains(&key_debug));
        assert!(rendered.contains("tls_key_pem_configured: true"));
    }
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
        let result = client.fetch_share("127.0.0.1:1", [0; 32], 0, 0).await;
        let err = result.unwrap_err();
        assert_eq!(err.phase, TransportPhase::Session);
        assert!(err.message.contains("WSS connect"));
    }

    #[tokio::test]
    async fn wss_multiple_shares_correct_slot_selection() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalShareStore::open(dir.path(), 100).unwrap());
        let params = DissolutionParams {
            data_shards: 3,
            total_shards: 5,
        };
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
        assert_eq!(
            parse_host_port("1.2.3.4:8080", 443),
            ("1.2.3.4".into(), 8080)
        );
        assert_eq!(
            parse_host_port("host.example.com", 443),
            ("host.example.com".into(), 443)
        );
        assert_eq!(
            parse_host_port("ws://127.0.0.1:9999/path", 443),
            ("127.0.0.1".into(), 9999)
        );
    }
}

// ─── Protocol and hardening tests ────────────────────────────────────────────

#[cfg(test)]
mod protocol_tests {
    use super::*;
    use crate::{
        pipeline::{dissolve, DissolutionParams},
        transport::ws_direct::WsDirectClient,
    };
    use futures::StreamExt;

    /// A record provider that hands out fixed bytes for one MID.
    struct FixedRecord {
        mid: [u8; 32],
        value: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl RecordProvider for FixedRecord {
        async fn record_value(&self, mid_digest: [u8; 32]) -> Option<Vec<u8>> {
            (mid_digest == self.mid).then(|| self.value.clone())
        }
    }

    async fn start(server: WssShareServer) -> u16 {
        let port = server.port;
        tokio::spawn(server.run());
        tokio::time::sleep(Duration::from_millis(30)).await;
        port
    }

    fn empty_store() -> (tempfile::TempDir, Arc<LocalShareStore>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalShareStore::open(dir.path(), 100).unwrap());
        (dir, store)
    }

    async fn raw_ws(port: u16) -> tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        tokio_tungstenite::client_async(format!("ws://127.0.0.1:{port}/"), tcp)
            .await
            .unwrap()
            .0
    }

    /// True once the server has ended the conversation (close frame, EOF or reset).
    async fn ends_without_answer(
        ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    ) -> bool {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
                Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => return true,
                Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
                Ok(Some(Ok(_))) => return false,
                Err(_) => return false,
            }
        }
    }

    #[test]
    fn wire_messages_round_trip_and_reject_every_deviation() {
        let req = WsRequest::Record {
            mid_digest: [7u8; 32],
        };
        let bytes = encode_ws_message(&req).unwrap();
        assert_eq!(bytes[0], WS_WIRE_VERSION);
        assert!(matches!(
            decode_ws_message::<WsRequest>(&bytes, WS_REQUEST_MAX_BYTES),
            Ok(WsRequest::Record { .. })
        ));

        // Wrong version, empty, trailing bytes, truncated, over the limit.
        let mut wrong_version = bytes.clone();
        wrong_version[0] = WS_WIRE_VERSION.wrapping_add(1);
        assert!(decode_ws_message::<WsRequest>(&wrong_version, 1024).is_err());
        assert!(decode_ws_message::<WsRequest>(&[], 1024).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_ws_message::<WsRequest>(&trailing, 1024).is_err());
        assert!(decode_ws_message::<WsRequest>(&bytes[..bytes.len() - 1], 1024).is_err());
        assert!(decode_ws_message::<WsRequest>(&bytes, bytes.len() - 1).is_err());
        // An unknown variant.
        let mut unknown = bytes.clone();
        unknown[1..5].copy_from_slice(&99u32.to_le_bytes());
        assert!(decode_ws_message::<WsRequest>(&unknown, 1024).is_err());
    }

    #[test]
    fn a_declared_length_cannot_size_an_allocation() {
        // Record response: variant 1, Some, then a Vec<u8> claiming u64::MAX bytes.
        let mut evil = vec![WS_WIRE_VERSION];
        evil.extend_from_slice(&1u32.to_le_bytes());
        evil.push(1);
        evil.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode_ws_message::<WsResponse>(&evil, WS_MAX_MESSAGE_BYTES).is_err());

        // Same for a share response with a huge declared payload.
        let mut evil = vec![WS_WIRE_VERSION];
        evil.extend_from_slice(&0u32.to_le_bytes());
        evil.push(1);
        evil.extend_from_slice(&[0xFF; 64]);
        assert!(decode_ws_message::<WsResponse>(&evil, WS_MAX_MESSAGE_BYTES).is_err());
    }

    #[tokio::test]
    async fn a_record_is_served_and_an_unknown_mid_gets_none() {
        let (_dir, store) = empty_store();
        let known = [0x42u8; 32];
        let value = vec![9u8; 5000];
        let server = WssShareServer::bind(store, 0)
            .await
            .unwrap()
            .with_record_provider(Arc::new(FixedRecord {
                mid: known,
                value: value.clone(),
            }));
        let port = start(server).await;
        let client = WsDirectClient::new(&format!("ws://127.0.0.1:{port}"), None).unwrap();

        assert_eq!(client.fetch_record(known).await.unwrap(), Some(value));
        assert_eq!(client.fetch_record([0x43u8; 32]).await.unwrap(), None);
        // Many requests over one connection.
        for _ in 0..20 {
            assert!(client.fetch_record(known).await.unwrap().is_some());
        }
    }

    #[tokio::test]
    async fn without_a_provider_or_over_the_cap_a_record_is_none() {
        let (_dir, store) = empty_store();
        let mid = [0x51u8; 32];

        // No provider at all.
        let port = start(WssShareServer::bind(store.clone(), 0).await.unwrap()).await;
        let client = WsDirectClient::new(&format!("ws://127.0.0.1:{port}"), None).unwrap();
        assert_eq!(client.fetch_record(mid).await.unwrap(), None);

        // A provider whose value exceeds the cap: refused, indistinguishable from "unknown".
        let server = WssShareServer::bind(store, 0)
            .await
            .unwrap()
            .with_record_provider(Arc::new(FixedRecord {
                mid,
                value: vec![0u8; WS_RECORD_MAX_BYTES + 1],
            }));
        let port = start(server).await;
        let client = WsDirectClient::new(&format!("ws://127.0.0.1:{port}"), None).unwrap();
        assert_eq!(client.fetch_record(mid).await.unwrap(), None);
    }

    #[tokio::test]
    async fn shares_and_records_share_a_connection_and_a_request_limit_redials() {
        let (_dir, store) = empty_store();
        let (mid, shares) = dissolve(
            b"direct receive protocol test payload",
            DissolutionParams {
                data_shards: 2,
                total_shards: 3,
            },
        )
        .unwrap();
        for s in &shares {
            store.put(s).unwrap();
        }
        let server = WssShareServer::bind(store, 0)
            .await
            .unwrap()
            .with_max_requests_per_connection(2);
        let port = start(server).await;
        let client = WsDirectClient::new(&format!("ws://127.0.0.1:{port}"), None).unwrap();

        // Far more requests than one connection serves: each is answered, the
        // client dials again when the server closes.
        for round in 0..7u16 {
            let slot = round % 3;
            let share = client
                .fetch_share(*mid.as_bytes(), 0, slot)
                .await
                .unwrap()
                .expect("share present");
            assert_eq!(share.slot_index, slot);
        }
        assert!(client
            .fetch_share(*mid.as_bytes(), 0, 9)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn malformed_and_hostile_frames_end_the_connection_without_an_answer() {
        let (_dir, store) = empty_store();
        let port = start(WssShareServer::bind(store, 0).await.unwrap()).await;

        // Garbage binary.
        let mut ws = raw_ws(port).await;
        ws.send(Message::Binary(vec![0xFF; 40])).await.unwrap();
        assert!(ends_without_answer(&mut ws).await);

        // The right version byte, then garbage.
        let mut ws = raw_ws(port).await;
        let mut m = vec![WS_WIRE_VERSION];
        m.extend_from_slice(&[0xAB; 60]);
        ws.send(Message::Binary(m)).await.unwrap();
        assert!(ends_without_answer(&mut ws).await);

        // A text message (for example a JSON control request): not this protocol.
        let mut ws = raw_ws(port).await;
        ws.send(Message::Text(
            r#"{"cmd":"Shutdown","token":"x"}"#.to_owned(),
        ))
        .await
        .unwrap();
        assert!(ends_without_answer(&mut ws).await);

        // A frame far above the request limit: refused on its header, closed.
        let mut ws = raw_ws(port).await;
        let _ = ws.send(Message::Binary(vec![1u8; 2 * 1024 * 1024])).await;
        assert!(ends_without_answer(&mut ws).await);

        // The server is unharmed and still answers a good request.
        let client = WsDirectClient::new(&format!("ws://127.0.0.1:{port}"), None).unwrap();
        assert_eq!(client.fetch_record([1u8; 32]).await.unwrap(), None);
    }

    #[tokio::test]
    async fn connections_over_the_cap_are_closed_and_slots_are_reused() {
        let (_dir, store) = empty_store();
        let server = WssShareServer::bind(store, 0)
            .await
            .unwrap()
            .with_max_concurrent(2);
        let port = start(server).await;

        // Two idle upgraded connections fill the cap.
        let a = raw_ws(port).await;
        let b = raw_ws(port).await;

        // The third is closed at once: it never completes the upgrade.
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let third = tokio::time::timeout(
            Duration::from_secs(5),
            tokio_tungstenite::client_async(format!("ws://127.0.0.1:{port}/"), tcp),
        )
        .await
        .expect("the server must answer or close promptly, not queue");
        assert!(third.is_err(), "a connection over the cap must be refused");

        // Free a slot: service resumes.
        drop(a);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let client = WsDirectClient::new(&format!("ws://127.0.0.1:{port}"), None).unwrap();
        assert_eq!(client.fetch_record([2u8; 32]).await.unwrap(), None);
        drop(b);
    }

    #[tokio::test]
    async fn a_silent_connection_is_dropped_after_the_idle_timeout() {
        let (_dir, store) = empty_store();
        let server = WssShareServer::bind(store, 0)
            .await
            .unwrap()
            .with_idle_timeout(Duration::from_millis(300));
        let port = start(server).await;

        let mut ws = raw_ws(port).await;
        let started = std::time::Instant::now();
        assert!(ends_without_answer(&mut ws).await);
        assert!(started.elapsed() < Duration::from_secs(4));

        // A peer that never even completes the upgrade is dropped too.
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let mut buf = Vec::new();
        let n = tokio::time::timeout(
            Duration::from_secs(4),
            tokio::io::AsyncReadExt::read_to_end(&mut tcp, &mut buf),
        )
        .await
        .expect("server must close a stalled handshake")
        .unwrap_or(0);
        assert_eq!(n, 0);
    }
}
