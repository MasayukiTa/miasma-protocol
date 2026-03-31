/// REALITY-inspired obfuscated QUIC transport — Phase 2 (Task 14).
///
/// # Threat model
/// Active probing: an adversary dials the Miasma listen port to determine
/// whether it is a "suspicious" service.  Without obfuscation this succeeds
/// because the Miasma/QUIC handshake is distinguishable from HTTPS.
///
/// # REALITY design (simplified)
/// REALITY was designed for Xray/V2Ray; Miasma adopts the core idea:
///
/// 1. **Shared secret** (`probe_secret`): a 32-byte key known only to
///    authorised clients.  A BLAKE3-MAC token derived from a random nonce
///    is sent as the first 64 bytes on the QUIC stream. The server verifies
///    this token before serving any share data.
///
/// 2. **Fingerprint template** (`browser_fingerprint`): the TLS handshake
///    (ALPN values) is set to match a real browser. DPI sees plausible
///    browser-like QUIC traffic.
///
/// 3. **Fallback proxy** (active-probing resistance): if a connection does NOT
///    contain a valid `probe_secret`, the server connects to `fallback_url` via
///    TCP+TLS and relays the conversation bidirectionally. Active probers (e.g.,
///    GFW) receive a real response from the fallback site and cannot distinguish
///    this server from a legitimate web service.
///
///    Limitation: the TLS certificate is still self-signed for the SNI domain.
///    Full REALITY requires the server to present the *real* site's certificate
///    by proxying the TLS handshake at the QUIC packet level (before TLS
///    completes), which requires raw QUIC interception not yet implemented.
///    This implementation provides stream-level forwarding after TLS, which
///    defeats passive fingerprinting and simple HTTP/2 active probes.
///
/// # Wire protocol
/// ```text
///   Client → Server (first frame on bidi stream):
///     [32 bytes: random nonce] [32 bytes: blake3_keyed_hash(probe_secret, nonce)]
///     [bincode: ShareFetchRequest]
///
///   Server → Client:
///     [bincode: ShareFetchResponse]
/// ```
///
/// # Transport layer
/// Uses `quinn` (QUIC) with `rustls` 0.23 for TLS 1.3.
/// - Server uses a self-signed certificate (generated at bind time or
///   supplied via `ObfuscatedConfig`).
/// - Client skips certificate verification (authentication is via
///   `probe_secret`, not PKI).
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use quinn::Endpoint;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

use crate::{
    network::node::{ShareFetchRequest, ShareFetchResponse},
    share::MiasmaShare,
    store::LocalShareStore,
    MiasmaError,
};

use super::payload::{
    PayloadTransport, PayloadTransportError, PayloadTransportKind, TransportPhase,
};
use super::{PluggableTransport, TransportStream};

// ─── Browser fingerprint ──────────────────────────────────────────────────────

/// Supported browser TLS fingerprints for camouflage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserFingerprint {
    /// Chrome 124 on Windows — most common globally.
    Chrome124,
    /// Firefox 125 on Linux.
    Firefox125,
    /// Safari 17 on macOS.
    Safari17,
}

impl BrowserFingerprint {
    /// ALPN values advertised by this browser.
    pub fn alpn_values(&self) -> &'static [&'static str] {
        match self {
            Self::Chrome124 | Self::Firefox125 => &["h2", "http/1.1"],
            Self::Safari17 => &["h2"],
        }
    }

    /// ALPN values as byte vectors (for rustls config).
    pub fn alpn_bytes(&self) -> Vec<Vec<u8>> {
        self.alpn_values()
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect()
    }

    /// User-Agent string (used in WebSocket fallback SNI).
    pub fn user_agent(&self) -> &'static str {
        match self {
            Self::Chrome124 => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
            Self::Firefox125 => "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
            Self::Safari17 => "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
        }
    }
}

// ─── Configuration ────────────────────────────────────────────────────────────

/// Configuration for the obfuscated QUIC transport.
#[derive(Debug, Clone)]
pub struct ObfuscatedConfig {
    /// 32-byte shared secret.  Clients embed this in the TLS handshake;
    /// servers use it to distinguish Miasma clients from active probers.
    pub probe_secret: [u8; 32],

    /// TLS fingerprint template used for camouflage.
    pub fingerprint: BrowserFingerprint,

    /// URL to which the server proxies connections that fail the
    /// `probe_secret` check.  Should be a real HTTPS URL (e.g. CDN).
    pub fallback_url: String,

    /// SNI hostname advertised in the TLS ClientHello.
    /// Should match the `fallback_url` domain.
    pub sni: String,

    /// DER-encoded server certificate. If `None`, a self-signed cert is
    /// generated at bind time (requires `rcgen` — available in dev-deps).
    pub server_cert_der: Option<Vec<u8>>,

    /// DER-encoded private key (PKCS#8). If `None`, generated with the cert.
    pub server_key_der: Option<Vec<u8>>,
}

impl ObfuscatedConfig {
    /// Create a config for a given relay server.
    ///
    /// # Example
    /// ```rust,ignore
    /// let cfg = ObfuscatedConfig::new(
    ///     my_probe_secret,
    ///     "cloudflare.com",
    ///     "https://cloudflare.com",
    ///     BrowserFingerprint::Chrome124,
    /// );
    /// ```
    pub fn new(
        probe_secret: [u8; 32],
        sni: impl Into<String>,
        fallback_url: impl Into<String>,
        fingerprint: BrowserFingerprint,
    ) -> Self {
        Self {
            probe_secret,
            fingerprint,
            fallback_url: fallback_url.into(),
            sni: sni.into(),
            server_cert_der: None,
            server_key_der: None,
        }
    }
}

// ─── BLAKE3-MAC authentication ────────────────────────────────────────────────

/// Size of the authentication nonce and token (bytes).
const AUTH_NONCE_LEN: usize = 32;
const AUTH_TOKEN_LEN: usize = 32;
const AUTH_HEADER_LEN: usize = AUTH_NONCE_LEN + AUTH_TOKEN_LEN;

/// Compute the BLAKE3-MAC token for the given nonce and probe_secret.
fn compute_auth_token(probe_secret: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    *blake3::keyed_hash(probe_secret, nonce).as_bytes()
}

/// Verify the BLAKE3-MAC token.
fn verify_auth_token(probe_secret: &[u8; 32], nonce: &[u8; 32], token: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    let expected = compute_auth_token(probe_secret, nonce);
    expected.ct_eq(token).into()
}

/// Generate a self-signed certificate for the given SNI domain.
fn generate_self_signed_cert(
    sni: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), MiasmaError> {
    let mut params = rcgen::CertificateParams::new(vec![sni.to_string()])
        .map_err(|e| MiasmaError::Sss(format!("cert params: {e}")))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, sni);
    let key_pair =
        rcgen::KeyPair::generate().map_err(|e| MiasmaError::Sss(format!("keygen: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| MiasmaError::Sss(format!("self-sign: {e}")))?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_pair.serialize_der(),
    ));
    Ok((cert_der, key_der))
}

// ─── Custom cert verifier (accept any — auth is via probe_secret) ────────────

/// A TLS certificate verifier that accepts any server certificate.
///
/// This is safe in Miasma's threat model because authentication is provided
/// by the BLAKE3-MAC probe_secret, not by TLS PKI. The self-signed cert
/// exists only to satisfy the QUIC/TLS handshake requirement.
#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Support all schemes that rustls knows about
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

// ─── Server ──────────────────────────────────────────────────────────────────

/// Obfuscated QUIC server — accepts connections, verifies probe_secret,
/// serves share requests.
pub struct ObfuscatedQuicServer {
    endpoint: Endpoint,
    store: Arc<LocalShareStore>,
    /// The port the server is actually bound to (useful when binding to port 0).
    pub port: u16,
    config: ObfuscatedConfig,
}

impl ObfuscatedQuicServer {
    /// Bind the obfuscated QUIC server with explicit cert/key.
    pub async fn bind_with_cert(
        store: Arc<LocalShareStore>,
        port: u16,
        config: ObfuscatedConfig,
        cert_der: CertificateDer<'static>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Self, MiasmaError> {
        // Build rustls server config (explicit ring provider)
        let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| MiasmaError::Sss(format!("TLS protocol versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| MiasmaError::Sss(format!("TLS server config: {e}")))?;

        tls_config.alpn_protocols = config.fingerprint.alpn_bytes();

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
                .map_err(|e| MiasmaError::Sss(format!("QUIC server config: {e}")))?,
        ));

        let addr: SocketAddr = ([0, 0, 0, 0], port).into();
        let endpoint = Endpoint::server(server_config, addr)
            .map_err(|e| MiasmaError::Sss(format!("QUIC bind {addr}: {e}")))?;

        let actual_port = endpoint
            .local_addr()
            .map_err(|e| MiasmaError::Sss(format!("local_addr: {e}")))?
            .port();

        info!(port = actual_port, "ObfuscatedQuicServer bound");

        Ok(Self {
            endpoint,
            store,
            port: actual_port,
            config,
        })
    }

    /// Bind with an auto-generated self-signed certificate (uses rcgen).
    /// Useful for production when no external CA is needed (auth is via probe_secret).
    pub async fn bind(
        store: Arc<LocalShareStore>,
        port: u16,
        config: ObfuscatedConfig,
    ) -> Result<Self, MiasmaError> {
        let sni = config.sni.clone();
        let (cert_der, key_der) = generate_self_signed_cert(&sni)?;
        Self::bind_with_cert(store, port, config, cert_der, key_der).await
    }

    /// Run the server loop. Accepts connections and handles each one.
    /// Call via `tokio::spawn(server.run())`.
    pub async fn run(self) {
        let probe_secret = self.config.probe_secret;
        let fallback_url = self.config.fallback_url.clone();
        let store = self.store;

        while let Some(incoming) = self.endpoint.accept().await {
            let store = store.clone();
            let fallback_url = fallback_url.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        if let Err(e) =
                            handle_obfuscated_connection(conn, &probe_secret, store, &fallback_url)
                                .await
                        {
                            debug!("ObfuscatedQuic connection error: {e}");
                        }
                    }
                    Err(e) => {
                        debug!("ObfuscatedQuic accept error: {e}");
                    }
                }
            });
        }
    }
}

// ─── Fallback transparent forwarding ─────────────────────────────────────────

/// Parse "https://hostname[:port][/path]" → (hostname, port).
fn parse_fallback_host(url: &str) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    // Strip any path component
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);

    // Split host:port
    let (host, port) = if let Some(colon) = authority.rfind(':') {
        let port_str = &authority[colon + 1..];
        match port_str.parse::<u16>() {
            Ok(p) => (&authority[..colon], p),
            Err(_) => (authority, 443u16),
        }
    } else {
        (authority, 443u16)
    };

    if host.is_empty() {
        return Err("empty fallback host".into());
    }
    Ok((host.to_string(), port))
}

/// Forward an unauthenticated QUIC stream to the fallback URL via TCP+TLS.
///
/// The bytes already read from the stream (`already_read`) are prepended
/// before forwarding, so the fallback server sees a complete request.
/// The fallback's response is relayed back to the QUIC client.
///
/// This makes active probers (e.g. GFW) receive a real response from the
/// fallback site rather than an immediate connection reset.
async fn forward_to_fallback(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    already_read: &[u8],
    fallback_url: &str,
) {
    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
        let (host, port) = parse_fallback_host(fallback_url)?;

        // TCP connect with 3s timeout
        let tcp = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::net::TcpStream::connect(format!("{host}:{port}")),
        )
        .await
        .map_err(|_| "fallback TCP connect timeout")?
        .map_err(|e| format!("fallback TCP connect {host}:{port}: {e}"))?;

        // TLS using system trust roots
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS protocol config: {e}"))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| format!("invalid server name {host}: {e}"))?;

        let mut tls = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            connector.connect(server_name, tcp),
        )
        .await
        .map_err(|_| "fallback TLS connect timeout")?
        .map_err(|e| format!("fallback TLS {host}: {e}"))?;

        // Forward bytes already read from the QUIC stream (the auth header
        // we consumed), then drain any remaining data.
        tls.write_all(already_read).await?;

        let mut buf = vec![0u8; 16384];
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_millis(300),
                recv.read(&mut buf),
            )
            .await
            {
                Ok(Ok(Some(n))) if n > 0 => tls.write_all(&buf[..n]).await?,
                _ => break,
            }
        }
        tls.flush().await?;

        // Relay response back to the QUIC client (5s timeout).
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tls.read(&mut buf),
        )
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);

        if n > 0 {
            send.write_all(&buf[..n]).await?;
            let _ = send.finish();
        }

        Ok(())
    }
    .await;

    if let Err(e) = result {
        debug!("ObfuscatedQuic fallback forward: {e}");
    }
}

// ─── Connection handler ───────────────────────────────────────────────────────

/// Handle a single obfuscated QUIC connection.
async fn handle_obfuscated_connection(
    conn: quinn::Connection,
    probe_secret: &[u8; 32],
    store: Arc<LocalShareStore>,
    fallback_url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut send, mut recv) = conn.accept_bi().await?;

    // 1. Read auth header: 32-byte nonce + 32-byte token
    let mut auth_buf = [0u8; AUTH_HEADER_LEN];
    recv.read_exact(&mut auth_buf).await?;

    let nonce: [u8; 32] = auth_buf[..AUTH_NONCE_LEN]
        .try_into()
        .map_err(|_| "auth nonce slice mismatch")?;
    let token: [u8; 32] = auth_buf[AUTH_NONCE_LEN..]
        .try_into()
        .map_err(|_| "auth token slice mismatch")?;

    if !verify_auth_token(probe_secret, &nonce, &token) {
        if !fallback_url.is_empty() {
            debug!("ObfuscatedQuic: invalid probe_secret — forwarding to fallback {fallback_url}");
            forward_to_fallback(&mut send, &mut recv, &auth_buf, fallback_url).await;
        } else {
            debug!("ObfuscatedQuic: invalid probe_secret — closing (no fallback configured)");
            conn.close(quinn::VarInt::from_u32(1), b"unauthorized");
        }
        return Ok(());
    }

    // 2. Read bincode ShareFetchRequest (length-prefixed: 4 bytes LE + body)
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let req_len = u32::from_le_bytes(len_buf) as usize;
    if req_len > 1024 * 1024 {
        warn!("ObfuscatedQuic: request too large ({req_len} bytes)");
        conn.close(quinn::VarInt::from_u32(2), b"request too large");
        return Ok(());
    }

    let mut req_buf = vec![0u8; req_len];
    recv.read_exact(&mut req_buf).await?;

    let request: ShareFetchRequest = bincode::deserialize(&req_buf)?;

    // 3. Look up the share
    let prefix: [u8; 8] = match request.mid_digest[..8].try_into() {
        Ok(p) => p,
        Err(_) => {
            warn!("ObfuscatedQuic: invalid mid_digest in request");
            conn.close(quinn::VarInt::from_u32(3), b"bad request");
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

    // 4. Send response: 4-byte LE length + bincode(ShareFetchResponse)
    let response = ShareFetchResponse { share };
    let body = bincode::serialize(&response)?;
    let len = (body.len() as u32).to_le_bytes();
    send.write_all(&len).await?;
    send.write_all(&body).await?;
    send.finish()?;

    // Wait until the peer has received all data (or the stream is reset).
    // Without this, dropping the handler may close the connection before
    // the response is fully delivered.
    let _ = send.stopped().await;

    Ok(())
}

// ─── Client (PayloadTransport) ───────────────────────────────────────────────

/// Obfuscated QUIC payload transport — implements `PayloadTransport`.
///
/// Connects to an `ObfuscatedQuicServer`, authenticates via probe_secret,
/// and fetches a share.
pub struct ObfuscatedQuicPayloadTransport {
    config: ObfuscatedConfig,
}

impl ObfuscatedQuicPayloadTransport {
    pub fn new(config: ObfuscatedConfig) -> Self {
        Self { config }
    }

    /// Build a quinn client endpoint with the accept-any-cert verifier.
    fn make_client_config(&self) -> Result<quinn::ClientConfig, PayloadTransportError> {
        let mut tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
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

        tls_config.alpn_protocols = self.config.fingerprint.alpn_bytes();

        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).map_err(|e| {
                PayloadTransportError {
                    phase: TransportPhase::Session,
                    message: format!("QUIC client config: {e}"),
                }
            })?,
        ));

        Ok(client_config)
    }
}

#[async_trait]
impl PayloadTransport for ObfuscatedQuicPayloadTransport {
    fn kind(&self) -> PayloadTransportKind {
        PayloadTransportKind::ObfuscatedQuic
    }

    async fn fetch_share(
        &self,
        peer_addr: &str,
        mid_digest: [u8; 32],
        slot_index: u16,
        segment_index: u32,
    ) -> Result<Option<MiasmaShare>, PayloadTransportError> {
        let client_config = self.make_client_config()?;

        // Parse peer address
        let addr: SocketAddr = peer_addr.parse().map_err(|e| PayloadTransportError {
            phase: TransportPhase::Session,
            message: format!("invalid peer address '{peer_addr}': {e}"),
        })?;

        // Create client endpoint on ephemeral port
        let mut endpoint =
            Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(|e| PayloadTransportError {
                phase: TransportPhase::Session,
                message: format!("QUIC client endpoint: {e}"),
            })?;
        endpoint.set_default_client_config(client_config);

        // Connect with SNI
        let conn = endpoint
            .connect(addr, &self.config.sni)
            .map_err(|e| PayloadTransportError {
                phase: TransportPhase::Session,
                message: format!("QUIC connect to {addr}: {e}"),
            })?
            .await
            .map_err(|e| PayloadTransportError {
                phase: TransportPhase::Session,
                message: format!("QUIC handshake with {addr}: {e}"),
            })?;

        // Open bidirectional stream
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| PayloadTransportError {
            phase: TransportPhase::Session,
            message: format!("open bidi stream: {e}"),
        })?;

        // 1. Send auth header: random nonce + BLAKE3-MAC token
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let token = compute_auth_token(&self.config.probe_secret, &nonce);

        send.write_all(&nonce)
            .await
            .map_err(|e| PayloadTransportError {
                phase: TransportPhase::Data,
                message: format!("write auth nonce: {e}"),
            })?;
        send.write_all(&token)
            .await
            .map_err(|e| PayloadTransportError {
                phase: TransportPhase::Data,
                message: format!("write auth token: {e}"),
            })?;

        // 2. Send ShareFetchRequest (length-prefixed bincode)
        let request = ShareFetchRequest {
            mid_digest,
            slot_index,
            segment_index,
        };
        let body = bincode::serialize(&request).map_err(|e| PayloadTransportError {
            phase: TransportPhase::Data,
            message: format!("serialize request: {e}"),
        })?;
        let len = (body.len() as u32).to_le_bytes();
        send.write_all(&len)
            .await
            .map_err(|e| PayloadTransportError {
                phase: TransportPhase::Data,
                message: format!("write request len: {e}"),
            })?;
        send.write_all(&body)
            .await
            .map_err(|e| PayloadTransportError {
                phase: TransportPhase::Data,
                message: format!("write request body: {e}"),
            })?;
        send.finish().map_err(|e| PayloadTransportError {
            phase: TransportPhase::Data,
            message: format!("finish send: {e}"),
        })?;

        // 3. Read response (length-prefixed bincode)
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf)
            .await
            .map_err(|e| PayloadTransportError {
                phase: TransportPhase::Data,
                message: format!("read response length: {e}"),
            })?;
        let resp_len = u32::from_le_bytes(len_buf) as usize;
        if resp_len > 64 * 1024 * 1024 {
            return Err(PayloadTransportError {
                phase: TransportPhase::Data,
                message: format!("response too large: {resp_len} bytes"),
            });
        }
        let mut resp_buf = vec![0u8; resp_len];
        recv.read_exact(&mut resp_buf)
            .await
            .map_err(|e| PayloadTransportError {
                phase: TransportPhase::Data,
                message: format!("read response body: {e}"),
            })?;

        let response: ShareFetchResponse =
            bincode::deserialize(&resp_buf).map_err(|e| PayloadTransportError {
                phase: TransportPhase::Data,
                message: format!("deserialize response: {e}"),
            })?;

        // Clean up
        conn.close(quinn::VarInt::from_u32(0), b"done");
        endpoint.wait_idle().await;

        Ok(response.share)
    }
}

// ─── Legacy PluggableTransport (kept for backward compatibility) ─────────────

pub struct ObfuscatedQuicTransport {
    config: ObfuscatedConfig,
}

impl ObfuscatedQuicTransport {
    pub fn new(config: ObfuscatedConfig) -> Self {
        Self { config }
    }
}

pub struct ObfuscatedStream;

impl TransportStream for ObfuscatedStream {
    fn as_bytes(&self) -> &[u8] {
        &[]
    }
}

#[async_trait]
impl PluggableTransport for ObfuscatedQuicTransport {
    fn name(&self) -> &'static str {
        "obfuscated-quic-reality"
    }

    async fn dial(&self, addr: &str) -> Result<Box<dyn TransportStream>, MiasmaError> {
        tracing::debug!(
            addr,
            sni = self.config.sni,
            fingerprint = ?self.config.fingerprint,
            "ObfuscatedQuic dial (legacy PluggableTransport — use ObfuscatedQuicPayloadTransport instead)"
        );
        Err(MiasmaError::Sss(
            "ObfuscatedQuic legacy transport: use ObfuscatedQuicPayloadTransport".into(),
        ))
    }

    async fn listen(&self, addr: &str) -> Result<(), MiasmaError> {
        tracing::debug!(
            addr,
            "ObfuscatedQuic listen (legacy PluggableTransport — use ObfuscatedQuicServer instead)"
        );
        Err(MiasmaError::Sss(
            "ObfuscatedQuic legacy transport: use ObfuscatedQuicServer".into(),
        ))
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- Existing tests (preserved) ---

    #[test]
    fn fingerprint_alpn_chrome() {
        let fp = BrowserFingerprint::Chrome124;
        assert!(fp.alpn_values().contains(&"h2"));
    }

    #[test]
    fn obfuscated_config_new() {
        let cfg = ObfuscatedConfig::new(
            [0u8; 32],
            "example.com",
            "https://example.com",
            BrowserFingerprint::Firefox125,
        );
        assert_eq!(cfg.sni, "example.com");
        assert_eq!(cfg.fingerprint, BrowserFingerprint::Firefox125);
    }

    #[test]
    fn obfuscated_transport_name() {
        let t = ObfuscatedQuicTransport::new(ObfuscatedConfig::new(
            [0u8; 32],
            "",
            "https://x.com",
            BrowserFingerprint::Chrome124,
        ));
        assert_eq!(t.name(), "obfuscated-quic-reality");
    }

    // --- New tests ---

    fn generate_test_cert(sni: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        generate_self_signed_cert(sni).unwrap()
    }

    #[test]
    fn auth_token_roundtrip() {
        let secret = [42u8; 32];
        let nonce = [7u8; 32];
        let token = compute_auth_token(&secret, &nonce);
        assert!(verify_auth_token(&secret, &nonce, &token));
    }

    #[test]
    fn auth_token_wrong_secret_rejected() {
        let secret_a = [42u8; 32];
        let secret_b = [99u8; 32];
        let nonce = [7u8; 32];
        let token = compute_auth_token(&secret_a, &nonce);
        assert!(!verify_auth_token(&secret_b, &nonce, &token));
    }

    #[test]
    fn obfuscated_quic_fingerprint_alpn() {
        let chrome = BrowserFingerprint::Chrome124;
        let alpn = chrome.alpn_bytes();
        assert_eq!(alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);

        let safari = BrowserFingerprint::Safari17;
        let alpn = safari.alpn_bytes();
        assert_eq!(alpn, vec![b"h2".to_vec()]);
    }

    #[tokio::test]
    async fn obfuscated_quic_roundtrip() {
        // 1. Create a temp store and put a share in it
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalShareStore::open(tmp.path(), 100).unwrap());

        let share = MiasmaShare {
            version: 1,
            mid_prefix: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            segment_index: 0,
            slot_index: 3,
            shard_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            key_share: vec![0x11, 0x22],
            shard_hash: [0xCC; 32],
            nonce: [0; 12],
            original_len: 4,
            timestamp: 12345,
        };
        store.put(&share).unwrap();

        // 2. Generate cert and config
        let probe_secret = [0x42u8; 32];
        let sni = "test.example.com";
        let (cert_der, key_der) = generate_test_cert(sni);

        let config = ObfuscatedConfig::new(
            probe_secret,
            sni,
            "https://example.com",
            BrowserFingerprint::Chrome124,
        );

        // 3. Start server
        let server = ObfuscatedQuicServer::bind_with_cert(
            store.clone(),
            0, // ephemeral port
            config.clone(),
            cert_der,
            key_der,
        )
        .await
        .unwrap();
        let port = server.port;
        tokio::spawn(server.run());

        // Give the server a moment to be ready
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // 4. Create client and fetch the share
        let client = ObfuscatedQuicPayloadTransport::new(config);
        let peer_addr = format!("127.0.0.1:{port}");

        // Build the mid_digest from the share's mid_prefix (pad with zeros)
        let mut mid_digest = [0u8; 32];
        mid_digest[..8].copy_from_slice(&share.mid_prefix);

        let result = client
            .fetch_share(&peer_addr, mid_digest, 3, 0)
            .await
            .expect("fetch_share should succeed");

        let fetched = result.unwrap();
        assert_eq!(fetched.slot_index, 3);
        assert_eq!(fetched.segment_index, 0);
        assert_eq!(fetched.shard_data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(fetched.timestamp, 12345);
    }

    #[tokio::test]
    async fn obfuscated_quic_wrong_secret_rejected() {
        // 1. Create a temp store
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalShareStore::open(tmp.path(), 100).unwrap());

        // 2. Server uses secret A, no fallback configured (empty string)
        //    so it closes the connection immediately on auth failure.
        let secret_a = [0x42u8; 32];
        let sni = "test.example.com";
        let (cert_der, key_der) = generate_test_cert(sni);

        let server_config = ObfuscatedConfig::new(
            secret_a,
            sni,
            "",  // no fallback — closes connection on bad secret
            BrowserFingerprint::Chrome124,
        );

        let server = ObfuscatedQuicServer::bind_with_cert(
            store.clone(),
            0,
            server_config,
            cert_der,
            key_der,
        )
        .await
        .unwrap();
        let port = server.port;
        tokio::spawn(server.run());

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 3. Client uses secret B (different!)
        let secret_b = [0x99u8; 32];
        let client_config = ObfuscatedConfig::new(
            secret_b,
            sni,
            "",
            BrowserFingerprint::Chrome124,
        );

        let client = ObfuscatedQuicPayloadTransport::new(client_config);
        let peer_addr = format!("127.0.0.1:{port}");

        let result = client.fetch_share(&peer_addr, [0u8; 32], 0, 0).await;

        // Should fail — server closes connection after auth failure (no fallback)
        assert!(result.is_err(), "expected error with wrong probe_secret");
        let err = result.unwrap_err();
        assert!(
            err.message.contains("reset")
                || err.message.contains("closed")
                || err.message.contains("connection")
                || err.message.contains("read")
                || err.message.contains("Application"),
            "unexpected error message: {}",
            err.message
        );
    }

    /// Verify that with a fallback configured, a wrong-secret connection does
    /// NOT cause an immediate protocol-level connection reset. The server
    /// attempts to forward to the fallback rather than closing with VarInt(1).
    /// (Network-dependent test: the fallback attempt may fail if no internet
    ///  is available, but the client sees a different error than a hard reset.)
    #[tokio::test]
    async fn obfuscated_quic_fallback_path_taken_on_wrong_secret() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalShareStore::open(tmp.path(), 100).unwrap());

        let secret_a = [0x42u8; 32];
        let sni = "test.example.com";
        let (cert_der, key_der) = generate_test_cert(sni);

        // Server configured with a fallback URL
        let server_config = ObfuscatedConfig::new(
            secret_a,
            sni,
            "https://example.com",  // fallback — connection forwarded, not hard-closed
            BrowserFingerprint::Chrome124,
        );

        let server = ObfuscatedQuicServer::bind_with_cert(
            store.clone(),
            0,
            server_config,
            cert_der,
            key_der,
        )
        .await
        .unwrap();
        let port = server.port;
        tokio::spawn(server.run());

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let secret_b = [0x99u8; 32];
        let client_config = ObfuscatedConfig::new(
            secret_b,
            sni,
            "https://example.com",
            BrowserFingerprint::Chrome124,
        );

        let client = ObfuscatedQuicPayloadTransport::new(client_config);
        let peer_addr = format!("127.0.0.1:{port}");

        // The call must fail (wrong secret → no valid share data returned),
        // but the error must NOT be "Application" close code 1 (hard-reject).
        // It will be a data-phase error because the stream carries fallback
        // response data (HTTP) rather than a valid ShareFetchResponse.
        let result = client.fetch_share(&peer_addr, [0u8; 32], 0, 0).await;
        assert!(result.is_err(), "expected error with wrong probe_secret");
        let err = result.unwrap_err();
        // With fallback, the server doesn't close with VarInt(1)/b"unauthorized".
        // The client gets malformed data (HTTP response), read error, or timeout.
        // "Application" with code 1 would mean the old hard-close path — that
        // must NOT appear when fallback is configured.
        assert!(
            !err.message.contains("code: 1"),
            "server must not hard-close with code 1 when fallback is configured; got: {}",
            err.message
        );
    }
}
