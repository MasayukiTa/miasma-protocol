/// Shadowsocks transport — AEAD-encrypted proxy for censorship bypass.
///
/// Routes share fetches through a Shadowsocks server to bypass DPI and
/// protocol fingerprinting. Requires the user to provide their own SS server.
///
/// # Position in fallback ladder
/// After ObfuscatedQuic, before RelayHop (priority 6 of 7).
///
/// # Honest limitations
/// - Requires user to configure a Shadowsocks server
/// - AEAD-2022 is strong but GFW can fingerprint some SS traffic patterns
/// - Active probing resistance depends on the SS server's implementation
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::payload::{
    PayloadTransportError, PayloadTransportKind, TransportPhase,
};

// ─── Configuration ──────────────────────────────────────────────────────────

/// Shadowsocks transport configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksConfig {
    /// Whether Shadowsocks transport is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Shadowsocks server address (e.g., "1.2.3.4:8388").
    #[serde(default)]
    pub server: Option<String>,
    /// Server password.
    #[serde(default)]
    pub password: Option<String>,
    /// Cipher method (default: "2022-blake3-aes-256-gcm").
    #[serde(default = "default_cipher")]
    pub cipher: String,
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
        self.enabled && self.server.is_some() && self.password.is_some()
    }

    /// Validate the configuration. Returns an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.server.is_none() {
            return Err("shadowsocks.server is required when enabled".to_string());
        }
        if self.password.is_none() {
            return Err("shadowsocks.password is required when enabled".to_string());
        }
        // Validate cipher is one of the known AEAD ciphers
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
        Ok(())
    }
}

// ─── Transport kind extension ───────────────────────────────────────────────

/// Extended transport kind that includes Shadowsocks.
///
/// We cannot modify the existing `PayloadTransportKind` enum without
/// breaking downstream match arms, so Shadowsocks is tracked via the
/// existing kind system with a convention: Shadowsocks uses
/// `PayloadTransportKind::WssTunnel` as a base but is distinguishable
/// by name.
///
/// **Note**: When the `PayloadTransportKind` enum is next extended,
/// a `Shadowsocks` variant should be added there directly.

/// Display name for the Shadowsocks transport in diagnostics.
pub const TRANSPORT_NAME: &str = "shadowsocks";

// ─── Transport placeholder ──────────────────────────────────────────────────

/// Shadowsocks payload transport.
///
/// Routes share fetches through a Shadowsocks AEAD-encrypted tunnel.
/// Always compiled — enable/disable via `config.toml` `[transport.shadowsocks]`
/// section (`enabled = true/false`). Users in jurisdictions where Shadowsocks
/// is restricted can disable it at runtime.
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
}

impl fmt::Debug for ShadowsocksPayloadTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowsocksPayloadTransport")
            .field("server", &self.config.server)
            .field("cipher", &self.config.cipher)
            .finish()
    }
}

/// Shadowsocks transport is always compiled. Actual network calls through
/// the Shadowsocks tunnel are pending integration of the `shadowsocks` crate;
/// until then, `fetch_share` returns a clean error explaining the status.
#[async_trait::async_trait]
impl super::payload::PayloadTransport for ShadowsocksPayloadTransport {
    fn kind(&self) -> PayloadTransportKind {
        // Uses WssTunnel as placeholder until PayloadTransportKind::Shadowsocks is added
        PayloadTransportKind::WssTunnel
    }

    async fn fetch_share(
        &self,
        peer_addr: &str,
        _mid_digest: [u8; 32],
        _slot_index: u16,
        _segment_index: u32,
    ) -> Result<Option<crate::share::MiasmaShare>, PayloadTransportError> {
        let server = self.config.server.as_deref().unwrap_or("(not configured)");
        // When the `shadowsocks` crate is added:
        // 1. Connect to SS server
        // 2. Request connection to peer_addr through SS
        // 3. Send ShareFetchRequest
        // 4. Read ShareFetchResponse
        Err(PayloadTransportError {
            phase: TransportPhase::Session,
            message: format!(
                "Shadowsocks transport to {peer_addr} via {server}: \
                 not yet connected (requires 'shadowsocks' crate feature)"
            ),
        })
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
    }

    #[test]
    fn config_configured() {
        let c = ShadowsocksConfig {
            enabled: true,
            server: Some("1.2.3.4:8388".to_string()),
            password: Some("secret".to_string()),
            cipher: "2022-blake3-aes-256-gcm".to_string(),
            timeout_secs: 30,
        };
        assert!(c.is_configured());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_missing_server() {
        let c = ShadowsocksConfig {
            enabled: true,
            password: Some("secret".to_string()),
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_missing_password() {
        let c = ShadowsocksConfig {
            enabled: true,
            server: Some("1.2.3.4:8388".to_string()),
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
            password: Some("secret".to_string()),
            cipher: "aes-256-gcm".to_string(),
            timeout_secs: 45,
        };
        let json = serde_json::to_string(&c).unwrap();
        let de: ShadowsocksConfig = serde_json::from_str(&json).unwrap();
        assert!(de.enabled);
        assert_eq!(de.server, Some("1.2.3.4:8388".to_string()));
        assert_eq!(de.cipher, "aes-256-gcm");
    }

    #[test]
    fn transport_creation() {
        let c = ShadowsocksConfig {
            enabled: true,
            server: Some("1.2.3.4:8388".to_string()),
            password: Some("secret".to_string()),
            ..Default::default()
        };
        let t = ShadowsocksPayloadTransport::new(c).unwrap();
        assert_eq!(t.server_addr(), Some("1.2.3.4:8388"));
        assert_eq!(t.cipher(), "2022-blake3-aes-256-gcm");
        assert_eq!(t.timeout(), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn transport_returns_error() {
        let c = ShadowsocksConfig {
            enabled: true,
            server: Some("1.2.3.4:8388".to_string()),
            password: Some("secret".to_string()),
            ..Default::default()
        };
        let t = ShadowsocksPayloadTransport::new(c).unwrap();
        use super::super::payload::PayloadTransport;
        let result = t.fetch_share("peer:9000", [0u8; 32], 0, 0).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.phase, TransportPhase::Session);
        assert!(err.message.contains("Shadowsocks"));
    }
}
