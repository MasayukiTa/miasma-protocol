//! Client side of "direct receive over a WebSocket tunnel".
//!
//! A sender with no open port publishes an outbound tunnel (for example
//! `cloudflared tunnel --url http://127.0.0.1:<wss_port>`) to the WebSocket
//! server its daemon already runs. A receiver that cannot reach the DHT (QUIC
//! and raw TCP are blocked on a managed network) dials that URL instead and asks
//! it, with the protocol in [`super::websocket`], for the transfer's record and
//! manifest and then for every piece.
//!
//! * One [`WsDirectClient`] per endpoint URL. It keeps a small pool of open
//!   connections and reuses them across requests (a share can be 8 MiB, so a
//!   fresh TCP + TLS + upgrade per piece would be mostly overhead); a connection
//!   the server has closed (idle, or its request limit) is replaced
//!   transparently, once, before an error is reported.
//! * For `wss://` the certificate is verified by the operating system's own
//!   verifier (which knows the public CAs and a corporate TLS-inspection CA) plus
//!   an optional extra CA. There is no way to switch verification off here. Everything sent
//!   is AES-GCM ciphertext checked against the manifest's piece commitments, so a
//!   party that does terminate the TLS (the tunnel provider, an inspecting
//!   proxy) sees ciphertext and the request metadata only.

use std::{fmt, sync::Arc, time::Duration};

use futures::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::Mutex,
};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};
use tracing::debug;

use super::websocket::{
    decode_ws_message, encode_ws_message, ws_limits, WsRequest, WsResponse, WS_MAX_MESSAGE_BYTES,
};
use crate::{network::node::ShareFetchRequest, share::MiasmaShare, MiasmaError};

/// The longest URL accepted.
pub const MAX_WS_URL_LEN: usize = 2048;
/// The largest extra CA bundle accepted (PEM text).
pub const MAX_CA_PEM_BYTES: usize = 256 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(20);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(90);
/// Idle connections kept for reuse.
const POOL_MAX: usize = 4;
/// Pings tolerated while waiting for one response.
const MAX_PINGS_PER_RESPONSE: usize = 16;

trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncIo for T {}

type Conn = WebSocketStream<Box<dyn AsyncIo>>;

/// Why a request to an endpoint failed.
#[derive(Debug, Clone)]
pub enum WsClientError {
    /// The TLS certificate was refused. Retrying cannot help.
    Certificate(String),
    /// Could not connect, upgrade, or the connection broke. May be transient.
    Connect(String),
    /// The endpoint answered, but not in this protocol.
    Protocol(String),
}

impl WsClientError {
    /// Whether trying again could succeed.
    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Certificate(_))
    }
}

impl fmt::Display for WsClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certificate(e) => write!(
                f,
                "the server's TLS certificate was not accepted ({e}). If this network inspects \
                 TLS, the inspecting proxy's root certificate must be trusted by the operating \
                 system, or given with --ca-cert FILE"
            ),
            Self::Connect(e) => write!(f, "cannot reach the endpoint: {e}"),
            Self::Protocol(e) => write!(f, "the endpoint did not answer as expected: {e}"),
        }
    }
}

impl std::error::Error for WsClientError {}

impl From<WsClientError> for MiasmaError {
    fn from(e: WsClientError) -> Self {
        MiasmaError::Network(e.to_string())
    }
}

/// A parsed `ws://` / `wss://` endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsEndpoint {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    /// Path and query, starting with `/`.
    pub request_uri: String,
}

impl WsEndpoint {
    /// Parse and check a URL. Only `ws://` and `wss://`; no credentials in the
    /// URL; a bounded length; a host.
    pub fn parse(url: &str) -> Result<Self, MiasmaError> {
        let bad = |why: &str| MiasmaError::Network(format!("invalid --via URL: {why}"));
        if url.len() > MAX_WS_URL_LEN {
            return Err(bad("too long"));
        }
        if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(bad("contains whitespace or control characters"));
        }
        let (tls, rest) = if let Some(r) = url.strip_prefix("wss://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("ws://") {
            (false, r)
        } else {
            return Err(bad("must start with wss:// or ws://"));
        };
        let split = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(split);
        if authority.contains('@') {
            return Err(bad("credentials in the URL are not supported"));
        }
        let (host, port) = if let Some(after) = authority.strip_prefix('[') {
            // [v6]:port
            let (h, p) = after
                .split_once(']')
                .ok_or_else(|| bad("unterminated [ ]"))?;
            let port = match p.strip_prefix(':') {
                Some(p) => Some(p),
                None if p.is_empty() => None,
                None => return Err(bad("text after the IPv6 address")),
            };
            (h.to_owned(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_owned(), Some(p)),
                None => (authority.to_owned(), None),
            }
        };
        if host.is_empty() {
            return Err(bad("no host"));
        }
        let port = match port {
            Some(p) => p.parse::<u16>().map_err(|_| bad("bad port"))?,
            None if tls => 443,
            None => 80,
        };
        if port == 0 {
            return Err(bad("bad port"));
        }
        let request_uri = match tail {
            "" => "/".to_owned(),
            t if t.starts_with('/') => t.split('#').next().unwrap_or("/").to_owned(),
            t if t.starts_with('?') => format!("/{}", t.split('#').next().unwrap_or("")),
            _ => "/".to_owned(),
        };
        Ok(Self {
            tls,
            host,
            port,
            request_uri,
        })
    }

    /// `host` or `[host]` as it appears in a URL authority.
    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("{host}:{}", self.port)
    }

    fn request_url(&self) -> String {
        format!(
            "{}://{}{}",
            if self.tls { "wss" } else { "ws" },
            self.authority(),
            self.request_uri
        )
    }
}

/// The TLS client configuration for `wss://`: the operating system's own
/// certificate verification, plus `extra_ca_pem` if given. Verification is always
/// on; there is no way to turn it off here.
///
/// "The operating system's verification" is `rustls-platform-verifier`: Windows
/// CryptoAPI, Apple's Security framework, or WebPKI over the platform's roots
/// elsewhere. It is used instead of loading the OS roots into a rustls store
/// because the two differ where it matters. Windows keeps its public roots
/// (which a Cloudflare tunnel's certificate chains to) out of the enumerable
/// root store until a chain needs them, and it distributes a corporate
/// TLS-inspection root by policy; only the OS verifier sees both. A real run
/// through a Cloudflare quick tunnel failed with `UnknownIssuer` against a store
/// loaded with `rustls-native-certs`, and that is why.
///
/// An unreadable *extra* CA is an error, never silently ignored. (Android's
/// verifier needs the host app to hand it a JVM, which this library does not
/// have; there the bundled Mozilla roots plus the extra CA are used.)
pub fn build_tls_connector(
    extra_ca_pem: Option<&[u8]>,
) -> Result<tokio_rustls::TlsConnector, MiasmaError> {
    // Ensure the ring crypto provider is installed (idempotent).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut extra: Vec<rustls::pki_types::CertificateDer<'static>> = Vec::new();
    if let Some(pem) = extra_ca_pem {
        if pem.len() > MAX_CA_PEM_BYTES {
            return Err(MiasmaError::Network("the CA file is too large".into()));
        }
        extra = rustls_pemfile::certs(&mut &*pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| MiasmaError::Network(format!("the CA file is not valid PEM: {e}")))?;
        if extra.is_empty() {
            return Err(MiasmaError::Network(
                "the CA file contains no certificate".into(),
            ));
        }
    }

    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| MiasmaError::Network(format!("TLS protocol versions: {e}")))?;
    let config = client_config(builder, provider, extra)?;
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

#[cfg(not(target_os = "android"))]
fn client_config(
    builder: rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    extra: Vec<rustls::pki_types::CertificateDer<'static>>,
) -> Result<rustls::ClientConfig, MiasmaError> {
    use rustls_platform_verifier::Verifier;
    let verifier = if extra.is_empty() {
        Verifier::new(provider)
    } else {
        Verifier::new_with_extra_roots(extra, provider)
    }
    .map_err(|e| MiasmaError::Network(format!("cannot start the OS certificate verifier: {e}")))?;
    Ok(builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

#[cfg(target_os = "android")]
fn client_config(
    builder: rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>,
    _provider: Arc<rustls::crypto::CryptoProvider>,
    extra: Vec<rustls::pki_types::CertificateDer<'static>>,
) -> Result<rustls::ClientConfig, MiasmaError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in extra {
        roots.add(cert).map_err(|e| {
            MiasmaError::Network(format!("the CA file has an unusable certificate: {e}"))
        })?;
    }
    Ok(builder.with_root_certificates(roots).with_no_client_auth())
}

/// A client for one endpoint, with connection reuse.
pub struct WsDirectClient {
    endpoint: WsEndpoint,
    tls: Option<tokio_rustls::TlsConnector>,
    pool: Mutex<Vec<Conn>>,
}

impl fmt::Debug for WsDirectClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WsDirectClient")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl WsDirectClient {
    /// `extra_ca_pem` is only used for `wss://`.
    pub fn new(url: &str, extra_ca_pem: Option<&[u8]>) -> Result<Self, MiasmaError> {
        let endpoint = WsEndpoint::parse(url)?;
        let tls = if endpoint.tls {
            Some(build_tls_connector(extra_ca_pem)?)
        } else {
            None
        };
        Ok(Self {
            endpoint,
            tls,
            pool: Mutex::new(Vec::new()),
        })
    }

    pub fn endpoint(&self) -> &WsEndpoint {
        &self.endpoint
    }

    /// `host:port`, for messages.
    pub fn display_addr(&self) -> String {
        self.endpoint.authority()
    }

    /// The record value (record + manifest trailer) for `mid_digest`, or `None`
    /// if the endpoint has none.
    pub async fn fetch_record(
        &self,
        mid_digest: [u8; 32],
    ) -> Result<Option<Vec<u8>>, WsClientError> {
        match self.round_trip(&WsRequest::Record { mid_digest }).await? {
            WsResponse::Record { value } => Ok(value),
            WsResponse::Share(_) => Err(WsClientError::Protocol(
                "a share answered a record request".into(),
            )),
        }
    }

    /// One share, or `None` if the endpoint does not hold it.
    pub async fn fetch_share(
        &self,
        mid_digest: [u8; 32],
        segment_index: u32,
        slot_index: u16,
    ) -> Result<Option<MiasmaShare>, WsClientError> {
        let request = WsRequest::Share(ShareFetchRequest {
            mid_digest,
            slot_index,
            segment_index,
        });
        match self.round_trip(&request).await? {
            WsResponse::Share(r) => Ok(r.share),
            WsResponse::Record { .. } => Err(WsClientError::Protocol(
                "a record answered a share request".into(),
            )),
        }
    }

    async fn round_trip(&self, request: &WsRequest) -> Result<WsResponse, WsClientError> {
        let message = encode_ws_message(request).map_err(WsClientError::Protocol)?;
        // A pooled connection may have been closed by the server since its last
        // use; that costs one retry on a fresh connection, not an error.
        let mut allow_reuse = true;
        loop {
            let pooled = if allow_reuse {
                self.pool.lock().await.pop()
            } else {
                None
            };
            let reused = pooled.is_some();
            let mut conn = match pooled {
                Some(c) => c,
                None => self.dial().await?,
            };
            match exchange(&mut conn, &message).await {
                Ok(response) => {
                    let mut pool = self.pool.lock().await;
                    if pool.len() < POOL_MAX {
                        pool.push(conn);
                    }
                    return Ok(response);
                }
                Err(e) if reused => {
                    debug!("pooled connection unusable ({e}); dialing again");
                    allow_reuse = false;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn dial(&self) -> Result<Conn, WsClientError> {
        let ep = &self.endpoint;
        let connect = |what: String| WsClientError::Connect(what);

        let tcp = tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((ep.host.as_str(), ep.port)),
        )
        .await
        .map_err(|_| connect(format!("connect to {} timed out", ep.authority())))?
        .map_err(|e| connect(format!("connect to {}: {e}", ep.authority())))?;
        let _ = tcp.set_nodelay(true);

        let io: Box<dyn AsyncIo> = match &self.tls {
            Some(connector) => {
                let name = rustls::pki_types::ServerName::try_from(ep.host.clone())
                    .map_err(|e| connect(format!("invalid TLS server name: {e}")))?;
                let stream = tokio::time::timeout(UPGRADE_TIMEOUT, connector.connect(name, tcp))
                    .await
                    .map_err(|_| connect("TLS handshake timed out".into()))?
                    .map_err(|e| {
                        // A verdict from the certificate verifier, as opposed to a
                        // network failure during the handshake.
                        let verdict = e
                            .get_ref()
                            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                            .map(|re| re.to_string());
                        match verdict {
                            Some(v) => WsClientError::Certificate(v),
                            None => connect(format!("TLS handshake: {e}")),
                        }
                    })?;
                Box::new(stream)
            }
            None => Box::new(tcp),
        };

        let (ws, _response) = tokio::time::timeout(
            UPGRADE_TIMEOUT,
            tokio_tungstenite::client_async_with_config(
                ep.request_url(),
                io,
                Some(ws_limits(WS_MAX_MESSAGE_BYTES)),
            ),
        )
        .await
        .map_err(|_| connect("WebSocket upgrade timed out".into()))?
        .map_err(|e| connect(format!("WebSocket upgrade: {e}")))?;
        Ok(ws)
    }
}

/// One request and its response on an open connection.
async fn exchange(conn: &mut Conn, message: &[u8]) -> Result<WsResponse, WsClientError> {
    tokio::time::timeout(WRITE_TIMEOUT, conn.send(Message::Binary(message.to_vec())))
        .await
        .map_err(|_| WsClientError::Connect("write timed out".into()))?
        .map_err(|e| WsClientError::Connect(format!("send: {e}")))?;

    let mut pings = 0usize;
    loop {
        let next = tokio::time::timeout(READ_TIMEOUT, conn.next())
            .await
            .map_err(|_| WsClientError::Connect("no response in time".into()))?;
        match next {
            Some(Ok(Message::Binary(data))) => {
                return decode_ws_message(&data, WS_MAX_MESSAGE_BYTES)
                    .map_err(WsClientError::Protocol)
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                pings += 1;
                if pings > MAX_PINGS_PER_RESPONSE {
                    return Err(WsClientError::Protocol("too many control frames".into()));
                }
            }
            Some(Ok(Message::Close(_))) | None => {
                return Err(WsClientError::Connect("the connection was closed".into()))
            }
            Some(Ok(_)) => return Err(WsClientError::Protocol("unexpected message type".into())),
            Some(Err(e)) => return Err(WsClientError::Connect(format!("receive: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_parsed_with_defaults() {
        let e = WsEndpoint::parse("wss://example.trycloudflare.com").unwrap();
        assert!(e.tls);
        assert_eq!(
            (e.host.as_str(), e.port),
            ("example.trycloudflare.com", 443)
        );
        assert_eq!(e.request_uri, "/");

        let e = WsEndpoint::parse("ws://127.0.0.1:8123/x/y?z=1#frag").unwrap();
        assert!(!e.tls);
        assert_eq!((e.host.as_str(), e.port), ("127.0.0.1", 8123));
        assert_eq!(e.request_uri, "/x/y?z=1");

        let e = WsEndpoint::parse("ws://[::1]:9/").unwrap();
        assert_eq!((e.host.as_str(), e.port), ("::1", 9));
        assert_eq!(e.request_url(), "ws://[::1]:9/");
        assert_eq!(WsEndpoint::parse("ws://h").unwrap().port, 80);
    }

    #[test]
    fn hostile_or_malformed_urls_are_refused() {
        for url in [
            "http://example.com",
            "https://example.com",
            "example.com:443",
            "wss://",
            "wss://:443",
            "wss://user:pw@example.com",
            "wss://example.com:0",
            "wss://example.com:99999",
            "wss://exa mple.com",
            "wss://example.com/\r\nHost: evil",
            "wss://[::1",
            "wss://[::1]x",
        ] {
            assert!(WsEndpoint::parse(url).is_err(), "{url:?} must be refused");
        }
        let long = format!("wss://example.com/{}", "a".repeat(MAX_WS_URL_LEN));
        assert!(WsEndpoint::parse(&long).is_err());
    }

    #[test]
    fn an_unreadable_extra_ca_is_an_error_not_ignored() {
        assert!(build_tls_connector(Some(b"not a pem file")).is_err());
        assert!(build_tls_connector(Some(&vec![b'x'; MAX_CA_PEM_BYTES + 1])).is_err());
        assert!(build_tls_connector(None).is_ok());
    }
}
