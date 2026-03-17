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
///    authorised clients.  Embedded in the TLS ClientHello as a custom
///    extension (or derived from the SNI random nonce).
///
/// 2. **Fingerprint template** (`browser_fingerprint`): the TLS handshake
///    (ClientHello cipher suites, extensions, elliptic curves) is copied
///    from a real browser (e.g. Chrome 124).  DPI sees a plausible browser
///    handshake.
///
/// 3. **Fallback proxy**: if a connection does NOT contain a valid
///    `probe_secret`, the server acts as a reverse proxy to a real CDN URL
///    (`fallback_url`).  The active prober receives a real HTTPS response
///    and cannot distinguish the node from a CDN origin.
///
/// # Phase 2 implementation plan
/// - Integrate with `rustls` custom `ClientHello` builder.
/// - The QUIC `initial_packet` carries the `probe_secret` encrypted under
///   the server's static X25519 public key (from `NodeKeys`).
/// - Server decrypts and checks; on failure, proxies to `fallback_url`.
use crate::MiasmaError;
use async_trait::async_trait;

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
        }
    }
}

// ─── Transport ────────────────────────────────────────────────────────────────

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
    fn as_bytes(&self) -> &[u8] { &[] }
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
            "ObfuscatedQuic dial (stub — Phase 2)"
        );
        // Phase 2: construct a QUIC initial packet with probe_secret,
        // apply browser fingerprint to TLS ClientHello, dial addr.
        Err(MiasmaError::Sss("ObfuscatedQuic transport not yet implemented (Phase 2)".into()))
    }

    async fn listen(&self, addr: &str) -> Result<(), MiasmaError> {
        tracing::debug!(addr, "ObfuscatedQuic listen (stub — Phase 2)");
        Err(MiasmaError::Sss("ObfuscatedQuic listen not yet implemented (Phase 2)".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            [0u8; 32], "", "https://x.com", BrowserFingerprint::Chrome124,
        ));
        assert_eq!(t.name(), "obfuscated-quic-reality");
    }
}
