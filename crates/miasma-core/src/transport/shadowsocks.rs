/// Shadowsocks transport — AEAD-2022 encrypted tunnel for censorship bypass.
///
/// Two modes:
/// - **Native** (preferred): Direct AEAD-2022 encrypted TCP tunnel to a
///   Shadowsocks server using `shadowsocks-crypto`. No external ss-local needed.
/// - **External**: SOCKS5 proxy through user-run ss-local. Fallback when native
///   is not configured or fails.
///
/// # Position in fallback ladder
/// After ObfuscatedQuic, before RelayHop (priority 6 of 7).
///
/// # Wire protocol (native mode)
/// AEAD-2022 TCP relay per SIP022 spec. Client sends salt + encrypted fixed
/// header (type=0x00, timestamp, variable header length) + encrypted variable
/// header (SOCKS5 address of peer, padding). Then length+payload chunks carry
/// the WebSocket upgrade and bincode ShareFetchRequest/Response.
///
/// # Honest limitations
/// - Requires user to configure a Shadowsocks server and base64 PSK
/// - AEAD-2022 is strong but GFW can fingerprint some SS traffic patterns
/// - Active probing resistance depends on the SS server's implementation
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

use super::payload::{PayloadTransportError, PayloadTransportKind, TransportPhase};

// ─── Configuration ──────────────────────────────────────────────────────────

/// Shadowsocks transport configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksConfig {
    /// Whether Shadowsocks transport is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Shadowsocks server address for native mode (e.g., "1.2.3.4:8388").
    #[serde(default)]
    pub server: Option<String>,
    /// Base64-encoded pre-shared key (for AEAD-2022 native mode).
    #[serde(default)]
    pub password: Option<String>,
    /// Cipher method (default: "2022-blake3-aes-256-gcm").
    #[serde(default = "default_cipher")]
    pub cipher: String,
    /// ss-local SOCKS5 address for external mode (e.g., "127.0.0.1:1080").
    #[serde(default)]
    pub local_addr: Option<String>,
    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

impl Default for ShadowsocksConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server: None,
            password: None,
            cipher: default_cipher(),
            local_addr: None,
            timeout_secs: default_timeout(),
        }
    }
}

fn default_cipher() -> String {
    "2022-blake3-aes-256-gcm".to_string()
}

fn default_timeout() -> u64 {
    30
}

impl ShadowsocksConfig {
    /// Whether the configuration is complete enough to attempt a connection.
    pub fn is_configured(&self) -> bool {
        self.enabled && (self.native_configured() || self.external_configured())
    }

    /// Whether native AEAD-2022 mode is configured.
    pub fn native_configured(&self) -> bool {
        self.server.is_some() && self.password.is_some() && self.is_aead_2022()
    }

    /// Whether external ss-local SOCKS5 mode is configured.
    pub fn external_configured(&self) -> bool {
        self.local_addr.is_some()
    }

    /// Whether the selected cipher is an AEAD-2022 cipher (required for native mode).
    fn is_aead_2022(&self) -> bool {
        matches!(
            self.cipher.as_str(),
            "2022-blake3-aes-256-gcm"
                | "2022-blake3-aes-128-gcm"
                | "2022-blake3-chacha20-poly1305"
        )
    }

    /// Validate the configuration. Returns an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.server.is_none() && self.local_addr.is_none() {
            return Err(
                "either shadowsocks.server (native) or shadowsocks.local_addr (external) is required when enabled"
                    .to_string(),
            );
        }
        if self.server.is_some() && self.password.is_some() {
            // Validate cipher for native mode
            let valid_ciphers = [
                "2022-blake3-aes-256-gcm",
                "2022-blake3-aes-128-gcm",
                "2022-blake3-chacha20-poly1305",
                "aes-256-gcm",
                "aes-128-gcm",
                "chacha20-ietf-poly1305",
            ];
            if !valid_ciphers.contains(&self.cipher.as_str()) {
                return Err(format!(
                    "unknown cipher '{}'. Valid: {}",
                    self.cipher,
                    valid_ciphers.join(", ")
                ));
            }
            // Validate base64 PSK for AEAD-2022
            if self.is_aead_2022() {
                let password = self.password.as_deref().unwrap();
                let key_bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    password,
                )
                .map_err(|e| format!("password must be base64-encoded PSK for AEAD-2022: {e}"))?;
                let expected_len = resolve_cipher_kind(&self.cipher)
                    .map(|k| k.key_len())
                    .unwrap_or(32);
                if key_bytes.len() != expected_len {
                    return Err(format!(
                        "PSK must be {expected_len} bytes (got {}). Generate with: openssl rand -base64 {expected_len}",
                        key_bytes.len()
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Map cipher string to shadowsocks-crypto CipherKind.
fn resolve_cipher_kind(cipher: &str) -> Option<shadowsocks_crypto::CipherKind> {
    match cipher {
        "2022-blake3-aes-256-gcm" => {
            Some(shadowsocks_crypto::CipherKind::AEAD2022_BLAKE3_AES_256_GCM)
        }
        "2022-blake3-aes-128-gcm" => {
            Some(shadowsocks_crypto::CipherKind::AEAD2022_BLAKE3_AES_128_GCM)
        }
        "2022-blake3-chacha20-poly1305" => {
            Some(shadowsocks_crypto::CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305)
        }
        _ => None,
    }
}

// ─── Transport kind ─────────────────────────────────────────────────────────

/// Display name for the Shadowsocks transport in diagnostics.
pub const TRANSPORT_NAME: &str = "shadowsocks";

// ─── Native AEAD-2022 tunnel ────────────────────────────────────────────────

/// Connect to a Shadowsocks server using native AEAD-2022 and return a
/// bidirectional stream tunneled to `target_host:target_port`.
///
/// Uses `tokio::io::duplex` + spawned relay tasks to provide an
/// `AsyncRead + AsyncWrite` interface over the encrypted chunked protocol.
async fn connect_native(
    server: &str,
    target_host: &str,
    target_port: u16,
    key: &[u8],
    kind: shadowsocks_crypto::CipherKind,
    timeout: Duration,
) -> Result<tokio::io::DuplexStream, PayloadTransportError> {
    use shadowsocks_crypto::v2::tcp::TcpCipher;

    let mut tcp = tokio::time::timeout(
        timeout,
        tokio::net::TcpStream::connect(server),
    )
    .await
    .map_err(|_| PayloadTransportError {
        phase: TransportPhase::Session,
        message: format!("SS native connect timeout to {server}"),
    })?
    .map_err(|e| PayloadTransportError {
        phase: TransportPhase::Session,
        message: format!("SS native connect to {server}: {e}"),
    })?;

    let salt_len = kind.salt_len();
    let tag_len = kind.tag_len(); // always 16

    // Generate random client salt
    let mut client_salt = vec![0u8; salt_len];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut client_salt);

    // --- Send client handshake ---

    // 1. Write salt (plaintext)
    tcp.write_all(&client_salt).await.map_err(|e| PayloadTransportError {
        phase: TransportPhase::Session,
        message: format!("SS write salt: {e}"),
    })?;

    let mut write_cipher = TcpCipher::new(kind, key, &client_salt);

    // 2. Build variable header (to know its length for fixed header)
    let mut var_header = Vec::new();
    if let Ok(ipv4) = target_host.parse::<std::net::Ipv4Addr>() {
        var_header.push(0x01);
        var_header.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = target_host.parse::<std::net::Ipv6Addr>() {
        var_header.push(0x04);
        var_header.extend_from_slice(&ipv6.octets());
    } else {
        // Domain name
        let host_bytes = target_host.as_bytes();
        if host_bytes.len() > 255 {
            return Err(PayloadTransportError {
                phase: TransportPhase::Session,
                message: "SS target hostname too long".to_string(),
            });
        }
        var_header.push(0x03);
        var_header.push(host_bytes.len() as u8);
        var_header.extend_from_slice(host_bytes);
    }
    var_header.extend_from_slice(&target_port.to_be_bytes());
    // Padding (random 1-64 bytes when no initial payload)
    let padding_len: u16 = rand::Rng::gen_range(&mut rand::thread_rng(), 1..=64);
    var_header.extend_from_slice(&padding_len.to_be_bytes());
    let padding_start = var_header.len();
    var_header.resize(padding_start + padding_len as usize, 0);
    rand::RngCore::fill_bytes(
        &mut rand::thread_rng(),
        &mut var_header[padding_start..],
    );

    // 3. Build and encrypt fixed header: type(1) + timestamp(8) + length(2) = 11 bytes
    let var_header_len = var_header.len() as u16;
    let mut fixed = Vec::with_capacity(11 + tag_len);
    fixed.push(0x00); // client request type
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    fixed.extend_from_slice(&ts.to_be_bytes());
    fixed.extend_from_slice(&var_header_len.to_be_bytes());
    fixed.resize(11 + tag_len, 0);
    write_cipher.encrypt_packet(&mut fixed);
    tcp.write_all(&fixed).await.map_err(|e| PayloadTransportError {
        phase: TransportPhase::Session,
        message: format!("SS write fixed header: {e}"),
    })?;

    // 4. Encrypt and write variable header
    var_header.resize(var_header.len() + tag_len, 0);
    write_cipher.encrypt_packet(&mut var_header);
    tcp.write_all(&var_header).await.map_err(|e| PayloadTransportError {
        phase: TransportPhase::Session,
        message: format!("SS write var header: {e}"),
    })?;

    tcp.flush().await.map_err(|e| PayloadTransportError {
        phase: TransportPhase::Session,
        message: format!("SS flush handshake: {e}"),
    })?;

    debug!("SS native handshake sent to {server} → {target_host}:{target_port}");

    // --- Relay tasks ---
    let (app_stream, relay_stream) = tokio::io::duplex(65536);
    let (relay_read, relay_write) = tokio::io::split(relay_stream);
    let (tcp_read, tcp_write) = tcp.into_split();

    let key_for_read = key.to_vec();
    let client_salt_for_read = client_salt.clone();

    // Write relay: app plaintext → encrypt as SS chunks → TCP
    tokio::spawn(async move {
        ss_write_relay(relay_read, tcp_write, write_cipher, tag_len).await;
    });

    // Read relay: TCP → decrypt SS chunks → app plaintext
    tokio::spawn(async move {
        ss_read_relay(
            tcp_read,
            relay_write,
            &key_for_read,
            &client_salt_for_read,
            kind,
            salt_len,
            tag_len,
        )
        .await;
    });

    Ok(app_stream)
}

/// Write relay: reads plaintext from app, encrypts as SS chunks, writes to TCP.
async fn ss_write_relay(
    mut app_read: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    mut tcp_write: tokio::net::tcp::OwnedWriteHalf,
    mut cipher: shadowsocks_crypto::v2::tcp::TcpCipher,
    tag_len: usize,
) {
    let mut buf = vec![0u8; 65536];
    loop {
        let n = match app_read.read(&mut buf[..65535]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };

        // Split into ≤65535 chunks (typically one)
        let mut sent = 0;
        while sent < n {
            let chunk_len = std::cmp::min(n - sent, 65535);

            // Encrypt length chunk (2 plaintext + tag)
            let mut len_buf = vec![0u8; 2 + tag_len];
            len_buf[0..2].copy_from_slice(&(chunk_len as u16).to_be_bytes());
            cipher.encrypt_packet(&mut len_buf);
            if tcp_write.write_all(&len_buf).await.is_err() {
                return;
            }

            // Encrypt payload chunk
            let mut payload_buf = vec![0u8; chunk_len + tag_len];
            payload_buf[..chunk_len].copy_from_slice(&buf[sent..sent + chunk_len]);
            cipher.encrypt_packet(&mut payload_buf);
            if tcp_write.write_all(&payload_buf).await.is_err() {
                return;
            }

            sent += chunk_len;
        }

        if tcp_write.flush().await.is_err() {
            return;
        }
    }
}

/// Read relay: reads encrypted SS chunks from TCP, decrypts, writes to app.
async fn ss_read_relay(
    mut tcp_read: tokio::net::tcp::OwnedReadHalf,
    mut app_write: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    key: &[u8],
    client_salt: &[u8],
    kind: shadowsocks_crypto::CipherKind,
    salt_len: usize,
    tag_len: usize,
) {
    use shadowsocks_crypto::v2::tcp::TcpCipher;

    // 1. Read server salt
    let mut server_salt = vec![0u8; salt_len];
    if tcp_read.read_exact(&mut server_salt).await.is_err() {
        return;
    }

    let mut read_cipher = TcpCipher::new(kind, key, &server_salt);

    // 2. Read + decrypt server fixed header
    // Response fixed header: type(1) + timestamp(8) + request_salt(salt_len) + length(2)
    let fixed_plaintext_len = 1 + 8 + salt_len + 2;
    let mut fixed_buf = vec![0u8; fixed_plaintext_len + tag_len];
    if tcp_read.read_exact(&mut fixed_buf).await.is_err() {
        return;
    }
    if !read_cipher.decrypt_packet(&mut fixed_buf) {
        warn!("SS response fixed header auth failed");
        return;
    }

    // Verify type byte
    if fixed_buf[0] != 0x01 {
        warn!("SS response type mismatch: {}", fixed_buf[0]);
        return;
    }

    // Verify echoed client salt
    if fixed_buf[9..9 + salt_len] != *client_salt {
        warn!("SS response salt mismatch");
        return;
    }

    // 3. Read first payload chunk (length from fixed header)
    let first_len_offset = 1 + 8 + salt_len;
    let first_payload_len = u16::from_be_bytes([
        fixed_buf[first_len_offset],
        fixed_buf[first_len_offset + 1],
    ]) as usize;

    if first_payload_len > 0 {
        let mut payload_buf = vec![0u8; first_payload_len + tag_len];
        if tcp_read.read_exact(&mut payload_buf).await.is_err() {
            return;
        }
        if !read_cipher.decrypt_packet(&mut payload_buf) {
            warn!("SS first payload auth failed");
            return;
        }
        if app_write
            .write_all(&payload_buf[..first_payload_len])
            .await
            .is_err()
        {
            return;
        }
    }

    // 4. Steady state: length chunk + payload chunk pairs
    loop {
        let len_wire = 2 + tag_len;
        let mut len_buf = vec![0u8; len_wire];
        if tcp_read.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        if !read_cipher.decrypt_packet(&mut len_buf) {
            warn!("SS length chunk auth failed");
            break;
        }

        let payload_len =
            u16::from_be_bytes([len_buf[0], len_buf[1]]) as usize;
        if payload_len == 0 {
            continue;
        }

        let mut payload_buf = vec![0u8; payload_len + tag_len];
        if tcp_read.read_exact(&mut payload_buf).await.is_err() {
            break;
        }
        if !read_cipher.decrypt_packet(&mut payload_buf) {
            warn!("SS payload auth failed");
            break;
        }

        if app_write
            .write_all(&payload_buf[..payload_len])
            .await
            .is_err()
        {
            break;
        }
        if app_write.flush().await.is_err() {
            break;
        }
    }
}

// ─── Transport ──────────────────────────────────────────────────────────────

/// Shadowsocks payload transport.
///
/// Routes share fetches through a Shadowsocks AEAD-2022 tunnel (native) or
/// through an external ss-local SOCKS5 proxy (external). Always compiled —
/// enable/disable via `config.toml` `[transport.shadowsocks]` section.
pub struct ShadowsocksPayloadTransport {
    config: ShadowsocksConfig,
}

impl ShadowsocksPayloadTransport {
    pub fn new(config: ShadowsocksConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self { config })
    }

    /// The configured server address.
    pub fn server_addr(&self) -> Option<&str> {
        self.config.server.as_deref()
    }

    /// The configured cipher.
    pub fn cipher(&self) -> &str {
        &self.config.cipher
    }

    /// Connection timeout.
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.config.timeout_secs)
    }

    /// Whether native AEAD-2022 mode is available.
    pub fn native_available(&self) -> bool {
        self.config.native_configured()
    }

    /// Whether external ss-local mode is available.
    pub fn external_available(&self) -> bool {
        self.config.external_configured()
    }

    /// Try native AEAD-2022 tunnel fetch.
    async fn fetch_native(
        &self,
        peer_addr: &str,
        mid_digest: [u8; 32],
        slot_index: u16,
        segment_index: u32,
    ) -> Result<Option<crate::share::MiasmaShare>, PayloadTransportError> {
        let server = self.config.server.as_deref().unwrap();
        let password = self.config.password.as_deref().unwrap();
        let kind = resolve_cipher_kind(&self.config.cipher).unwrap();
        let timeout_dur = self.timeout();

        // Decode base64 PSK
        let key = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            password,
        )
        .map_err(|e| PayloadTransportError {
            phase: TransportPhase::Session,
            message: format!("SS PSK decode: {e}"),
        })?;

        let (host, port) = super::websocket::parse_host_port(peer_addr, 443);

        // Connect native AEAD-2022 tunnel
        let tunnel = connect_native(server, &host, port, &key, kind, timeout_dur).await?;

        // WebSocket upgrade over the tunnel
        let ws_url = format!("ws://{host}:{port}/static/v2/bundle.js");
        let (ws_stream, _) = tokio::time::timeout(
            timeout_dur,
            tokio_tungstenite::client_async(&ws_url, tunnel),
        )
        .await
        .map_err(|_| PayloadTransportError {
            phase: TransportPhase::Session,
            message: format!("SS native WS upgrade timeout to {peer_addr}"),
        })?
        .map_err(|e| PayloadTransportError {
            phase: TransportPhase::Session,
            message: format!("SS native WS upgrade to {peer_addr}: {e}"),
        })?;

        super::websocket::wss_request_response(
            ws_stream,
            mid_digest,
            slot_index,
            segment_index,
            timeout_dur,
            timeout_dur,
            16 * 1024 * 1024,
        )
        .await
    }

    /// Try external ss-local SOCKS5 fetch.
    async fn fetch_external(
        &self,
        peer_addr: &str,
        mid_digest: [u8; 32],
        slot_index: u16,
        segment_index: u32,
    ) -> Result<Option<crate::share::MiasmaShare>, PayloadTransportError> {
        let local_addr = self.config.local_addr.as_deref().ok_or(PayloadTransportError {
            phase: TransportPhase::Session,
            message: "SS external: local_addr not configured".to_string(),
        })?;

        let timeout_dur = self.timeout();
        let (host, port) = super::websocket::parse_host_port(peer_addr, 443);

        // Connect through ss-local SOCKS5
        let proxy_stream = tokio::time::timeout(
            timeout_dur,
            tokio_socks::tcp::Socks5Stream::connect(local_addr, (host.as_str(), port)),
        )
        .await
        .map_err(|_| PayloadTransportError {
            phase: TransportPhase::Session,
            message: format!("SS external SOCKS5 connect timeout to {local_addr}"),
        })?
        .map_err(|e| PayloadTransportError {
            phase: TransportPhase::Session,
            message: format!("SS external SOCKS5 via {local_addr}: {e}"),
        })?;

        let tcp_stream = proxy_stream.into_inner();
        let ws_url = format!("ws://{host}:{port}/static/v2/bundle.js");
        let (ws_stream, _) = tokio::time::timeout(
            timeout_dur,
            tokio_tungstenite::client_async(&ws_url, tcp_stream),
        )
        .await
        .map_err(|_| PayloadTransportError {
            phase: TransportPhase::Session,
            message: format!("SS external WS upgrade timeout to {peer_addr}"),
        })?
        .map_err(|e| PayloadTransportError {
            phase: TransportPhase::Session,
            message: format!("SS external WS upgrade to {peer_addr}: {e}"),
        })?;

        super::websocket::wss_request_response(
            ws_stream,
            mid_digest,
            slot_index,
            segment_index,
            timeout_dur,
            timeout_dur,
            16 * 1024 * 1024,
        )
        .await
    }
}

impl fmt::Debug for ShadowsocksPayloadTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowsocksPayloadTransport")
            .field("server", &self.config.server)
            .field("cipher", &self.config.cipher)
            .field("native", &self.config.native_configured())
            .field("external", &self.config.external_configured())
            .finish()
    }
}

/// Tries native AEAD-2022 first, falls back to external SOCKS5.
#[async_trait::async_trait]
impl super::payload::PayloadTransport for ShadowsocksPayloadTransport {
    fn kind(&self) -> PayloadTransportKind {
        PayloadTransportKind::WssTunnel
    }

    async fn fetch_share(
        &self,
        peer_addr: &str,
        mid_digest: [u8; 32],
        slot_index: u16,
        segment_index: u32,
    ) -> Result<Option<crate::share::MiasmaShare>, PayloadTransportError> {
        let mut last_err = None;

        // Try native AEAD-2022 first
        if self.config.native_configured() {
            match self
                .fetch_native(peer_addr, mid_digest, slot_index, segment_index)
                .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    warn!("SS native failed: {}", e.message);
                    last_err = Some(e);
                }
            }
        }

        // Try external SOCKS5
        if self.config.external_configured() {
            return self
                .fetch_external(peer_addr, mid_digest, slot_index, segment_index)
                .await;
        }

        Err(last_err.unwrap_or(PayloadTransportError {
            phase: TransportPhase::Session,
            message: "SS not configured (need server+password for native or local_addr for external)".to_string(),
        }))
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default() {
        let c = ShadowsocksConfig::default();
        assert!(!c.enabled);
        assert!(!c.is_configured());
        assert!(!c.native_configured());
        assert!(!c.external_configured());
    }

    #[test]
    fn config_native_configured() {
        let c = ShadowsocksConfig {
            enabled: true,
            server: Some("1.2.3.4:8388".to_string()),
            password: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &[0u8; 32],
            )),
            cipher: "2022-blake3-aes-256-gcm".to_string(),
            ..Default::default()
        };
        assert!(c.is_configured());
        assert!(c.native_configured());
        assert!(!c.external_configured());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_external_configured() {
        let c = ShadowsocksConfig {
            enabled: true,
            local_addr: Some("127.0.0.1:1080".to_string()),
            ..Default::default()
        };
        assert!(c.is_configured());
        assert!(!c.native_configured());
        assert!(c.external_configured());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_both_modes() {
        let c = ShadowsocksConfig {
            enabled: true,
            server: Some("1.2.3.4:8388".to_string()),
            password: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &[0u8; 32],
            )),
            cipher: "2022-blake3-aes-256-gcm".to_string(),
            local_addr: Some("127.0.0.1:1080".to_string()),
            ..Default::default()
        };
        assert!(c.native_configured());
        assert!(c.external_configured());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_missing_both() {
        let c = ShadowsocksConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_invalid_cipher() {
        let c = ShadowsocksConfig {
            enabled: true,
            server: Some("1.2.3.4:8388".to_string()),
            password: Some("secret".to_string()),
            cipher: "invalid-cipher".to_string(),
            ..Default::default()
        };
        let err = c.validate().unwrap_err();
        assert!(err.contains("unknown cipher"));
    }

    #[test]
    fn config_bad_base64_psk() {
        let c = ShadowsocksConfig {
            enabled: true,
            server: Some("1.2.3.4:8388".to_string()),
            password: Some("not-valid-base64!!!".to_string()),
            cipher: "2022-blake3-aes-256-gcm".to_string(),
            ..Default::default()
        };
        let err = c.validate().unwrap_err();
        assert!(err.contains("base64"));
    }

    #[test]
    fn config_wrong_psk_length() {
        let c = ShadowsocksConfig {
            enabled: true,
            server: Some("1.2.3.4:8388".to_string()),
            password: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &[0u8; 16], // 16 bytes but AES-256 needs 32
            )),
            cipher: "2022-blake3-aes-256-gcm".to_string(),
            ..Default::default()
        };
        let err = c.validate().unwrap_err();
        assert!(err.contains("32 bytes"));
    }

    #[test]
    fn config_aes128_psk_length() {
        let c = ShadowsocksConfig {
            enabled: true,
            server: Some("1.2.3.4:8388".to_string()),
            password: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &[0u8; 16], // 16 bytes for AES-128
            )),
            cipher: "2022-blake3-aes-128-gcm".to_string(),
            ..Default::default()
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_disabled_skips_validation() {
        let c = ShadowsocksConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_serde() {
        let c = ShadowsocksConfig {
            enabled: true,
            server: Some("1.2.3.4:8388".to_string()),
            password: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &[0u8; 32],
            )),
            cipher: "2022-blake3-aes-256-gcm".to_string(),
            local_addr: Some("127.0.0.1:1080".to_string()),
            timeout_secs: 45,
        };
        let json = serde_json::to_string(&c).unwrap();
        let de: ShadowsocksConfig = serde_json::from_str(&json).unwrap();
        assert!(de.enabled);
        assert_eq!(de.server, Some("1.2.3.4:8388".to_string()));
        assert_eq!(de.local_addr, Some("127.0.0.1:1080".to_string()));
        assert_eq!(de.cipher, "2022-blake3-aes-256-gcm");
    }

    #[test]
    fn config_serde_backward_compat() {
        // Old config without local_addr should deserialize fine
        let json = r#"{"enabled":true,"server":"1.2.3.4:8388","password":"test","cipher":"aes-256-gcm","timeout_secs":30}"#;
        let c: ShadowsocksConfig = serde_json::from_str(json).unwrap();
        assert!(c.local_addr.is_none());
    }

    #[test]
    fn resolve_cipher_kinds() {
        assert!(resolve_cipher_kind("2022-blake3-aes-256-gcm").is_some());
        assert!(resolve_cipher_kind("2022-blake3-aes-128-gcm").is_some());
        assert!(resolve_cipher_kind("2022-blake3-chacha20-poly1305").is_some());
        assert!(resolve_cipher_kind("aes-256-gcm").is_none());
        assert!(resolve_cipher_kind("unknown").is_none());
    }

    #[test]
    fn transport_creation_native() {
        let c = ShadowsocksConfig {
            enabled: true,
            server: Some("1.2.3.4:8388".to_string()),
            password: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &[0u8; 32],
            )),
            ..Default::default()
        };
        let t = ShadowsocksPayloadTransport::new(c).unwrap();
        assert!(t.native_available());
        assert!(!t.external_available());
        assert_eq!(t.cipher(), "2022-blake3-aes-256-gcm");
    }

    #[test]
    fn transport_creation_external() {
        let c = ShadowsocksConfig {
            enabled: true,
            local_addr: Some("127.0.0.1:1080".to_string()),
            ..Default::default()
        };
        let t = ShadowsocksPayloadTransport::new(c).unwrap();
        assert!(!t.native_available());
        assert!(t.external_available());
    }

    #[test]
    fn cipher_kind_key_lengths() {
        use shadowsocks_crypto::CipherKind;
        let aes256 = CipherKind::AEAD2022_BLAKE3_AES_256_GCM;
        assert_eq!(aes256.key_len(), 32);
        assert_eq!(aes256.salt_len(), 32);
        assert_eq!(aes256.tag_len(), 16);

        let aes128 = CipherKind::AEAD2022_BLAKE3_AES_128_GCM;
        assert_eq!(aes128.key_len(), 16);
        assert_eq!(aes128.salt_len(), 16);
    }

    /// Verify native AEAD-2022 encryption roundtrip using TcpCipher directly.
    #[test]
    fn aead_2022_encrypt_decrypt_roundtrip() {
        use shadowsocks_crypto::v2::tcp::TcpCipher;
        use shadowsocks_crypto::CipherKind;

        let kind = CipherKind::AEAD2022_BLAKE3_AES_256_GCM;
        let key = [42u8; 32];
        let salt = [7u8; 32];

        let mut enc = TcpCipher::new(kind, &key, &salt);
        let mut dec = TcpCipher::new(kind, &key, &salt);

        // Encrypt a length chunk
        let payload_len: u16 = 13;
        let mut len_buf = vec![0u8; 2 + 16];
        len_buf[0..2].copy_from_slice(&payload_len.to_be_bytes());
        enc.encrypt_packet(&mut len_buf);

        // Decrypt the length chunk
        assert!(dec.decrypt_packet(&mut len_buf));
        let decoded_len = u16::from_be_bytes([len_buf[0], len_buf[1]]);
        assert_eq!(decoded_len, 13);

        // Encrypt a payload chunk
        let plaintext = b"Hello, SS2022";
        let mut payload_buf = vec![0u8; plaintext.len() + 16];
        payload_buf[..plaintext.len()].copy_from_slice(plaintext);
        enc.encrypt_packet(&mut payload_buf);

        // Decrypt the payload chunk
        assert!(dec.decrypt_packet(&mut payload_buf));
        assert_eq!(&payload_buf[..plaintext.len()], plaintext);
    }

    /// Verify that wrong key fails authentication.
    #[test]
    fn aead_2022_wrong_key_fails() {
        use shadowsocks_crypto::v2::tcp::TcpCipher;
        use shadowsocks_crypto::CipherKind;

        let kind = CipherKind::AEAD2022_BLAKE3_AES_256_GCM;
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let salt = [0u8; 32];

        let mut enc = TcpCipher::new(kind, &key1, &salt);
        let mut dec = TcpCipher::new(kind, &key2, &salt);

        let mut buf = vec![0u8; 2 + 16];
        buf[0..2].copy_from_slice(&42u16.to_be_bytes());
        enc.encrypt_packet(&mut buf);

        assert!(!dec.decrypt_packet(&mut buf));
    }

    #[tokio::test]
    async fn native_connection_error() {
        let c = ShadowsocksConfig {
            enabled: true,
            server: Some("127.0.0.1:1".to_string()),
            password: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &[0u8; 32],
            )),
            timeout_secs: 2,
            ..Default::default()
        };
        let t = ShadowsocksPayloadTransport::new(c).unwrap();
        use super::super::payload::PayloadTransport;
        let result = t.fetch_share("peer:9000", [0u8; 32], 0, 0).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.phase, TransportPhase::Session);
        assert!(err.message.contains("SS"));
    }

    #[tokio::test]
    async fn external_connection_error() {
        let c = ShadowsocksConfig {
            enabled: true,
            local_addr: Some("127.0.0.1:1".to_string()),
            timeout_secs: 2,
            ..Default::default()
        };
        let t = ShadowsocksPayloadTransport::new(c).unwrap();
        use super::super::payload::PayloadTransport;
        let result = t.fetch_share("peer:9000", [0u8; 32], 0, 0).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.phase, TransportPhase::Session);
        assert!(err.message.contains("SS external"));
    }

    #[tokio::test]
    async fn fallback_native_to_external() {
        // Both configured but both unreachable — should try native then external
        let c = ShadowsocksConfig {
            enabled: true,
            server: Some("127.0.0.1:1".to_string()),
            password: Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &[0u8; 32],
            )),
            local_addr: Some("127.0.0.1:2".to_string()),
            timeout_secs: 2,
            ..Default::default()
        };
        let t = ShadowsocksPayloadTransport::new(c).unwrap();
        use super::super::payload::PayloadTransport;
        let result = t.fetch_share("peer:9000", [0u8; 32], 0, 0).await;
        assert!(result.is_err());
        // Should show external error (last tried)
        let err = result.unwrap_err();
        assert!(err.message.contains("SS external"));
    }
}
