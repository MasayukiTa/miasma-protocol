/// Tor transport — onion-routed anonymity for censored environments.
///
/// Routes share fetches through the Tor network for anonymity and
/// censorship circumvention. Supports two modes:
/// 1. Embedded Arti (Tor in-process) — requires `arti-client` crate feature
/// 2. External Tor proxy (SOCKS5) — uses existing proxy infrastructure
///
/// # Position in fallback ladder
/// Last (priority 7 of 7) — slowest but most censorship-resistant.
///
/// # Composition with Miasma onion routing
/// - Tor provides circuit-level anonymity to the Internet
/// - Miasma's Phase 4d onion routing provides per-hop content-blindness within the overlay
/// - These compose naturally: Tor hides IP from first Miasma peer, Miasma onion hides content
/// - NOT Tor-over-Tor: Miasma onion is application-layer XChaCha20-Poly1305
///
/// # Honest limitations
/// - Arti is pre-1.0; API may change
/// - 2-8 seconds circuit establishment latency
/// - Some countries block Tor directory authorities AND all known bridges
/// - ~5-10MB binary size increase (feature-gated)
/// - Arti on iOS untested upstream
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::payload::{
    PayloadTransportError, PayloadTransportKind, TransportPhase,
};

// ─── Configuration ──────────────────────────────────────────────────────────

/// Tor transport configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConfig {
    /// Whether Tor transport is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Use embedded Arti Tor client (vs external SOCKS5 proxy).
    #[serde(default)]
    pub use_embedded: bool,
    /// External Tor SOCKS5 port (default: 9050).
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    /// Tor bridge lines for censored environments.
    #[serde(default)]
    pub bridges: Vec<String>,
    /// Circuit build timeout in seconds.
    #[serde(default = "default_circuit_timeout")]
    pub circuit_timeout_secs: u64,
    /// Directory for Tor state/cache persistence.
    #[serde(default)]
    pub state_dir: Option<String>,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            use_embedded: false,
            socks_port: default_socks_port(),
            bridges: Vec::new(),
            circuit_timeout_secs: default_circuit_timeout(),
            state_dir: None,
        }
    }
}

fn default_socks_port() -> u16 {
    9050
}

fn default_circuit_timeout() -> u64 {
    30
}

impl TorConfig {
    /// Whether the configuration is complete enough to attempt a connection.
    pub fn is_configured(&self) -> bool {
        if !self.enabled {
            return false;
        }
        // External mode just needs a SOCKS port
        if !self.use_embedded {
            return true;
        }
        // Embedded mode is always configured (Arti bootstraps itself)
        true
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if !self.use_embedded && self.socks_port == 0 {
            return Err("tor.socks_port must be non-zero in external mode".to_string());
        }
        for (i, bridge) in self.bridges.iter().enumerate() {
            if bridge.is_empty() {
                return Err(format!("tor.bridges[{i}] is empty"));
            }
        }
        Ok(())
    }

    /// Get the Tor state directory, defaulting to `{data_dir}/tor/`.
    pub fn state_dir(&self, data_dir: &std::path::Path) -> PathBuf {
        self.state_dir
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("tor"))
    }
}

// ─── Transport ──────────────────────────────────────────────────────────────

/// Display name for diagnostics.
pub const TRANSPORT_NAME: &str = "tor";

/// Tor payload transport.
///
/// Always compiled — enable/disable via `config.toml` `[transport.tor]`
/// section (`enabled = true/false`). Users in jurisdictions where Tor
/// is restricted can disable it at runtime.
///
/// When using external Tor, this delegates to the existing SOCKS5 proxy
/// infrastructure in `proxy.rs`. When using embedded Arti, it manages
/// a `TorClient` in-process.
pub struct TorPayloadTransport {
    config: TorConfig,
    mode: TorMode,
}

/// Which Tor mode is active.
#[derive(Debug, Clone)]
enum TorMode {
    /// External Tor daemon via SOCKS5.
    External { socks_addr: String },
    /// Embedded Arti (requires feature flag).
    Embedded,
}

impl TorPayloadTransport {
    /// Create a new Tor transport from configuration.
    pub fn new(config: TorConfig) -> Result<Self, String> {
        config.validate()?;
        let mode = if config.use_embedded {
            TorMode::Embedded
        } else {
            TorMode::External {
                socks_addr: format!("127.0.0.1:{}", config.socks_port),
            }
        };
        Ok(Self { config, mode })
    }

    /// The configured mode.
    pub fn mode_name(&self) -> &str {
        match &self.mode {
            TorMode::External { .. } => "external-socks5",
            TorMode::Embedded => "embedded-arti",
        }
    }

    /// Whether bridges are configured.
    pub fn has_bridges(&self) -> bool {
        !self.config.bridges.is_empty()
    }

    /// Circuit build timeout.
    pub fn circuit_timeout(&self) -> Duration {
        Duration::from_secs(self.config.circuit_timeout_secs)
    }
}

impl fmt::Debug for TorPayloadTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TorPayloadTransport")
            .field("mode", &self.mode)
            .field("bridges", &self.config.bridges.len())
            .finish()
    }
}

#[async_trait::async_trait]
impl super::payload::PayloadTransport for TorPayloadTransport {
    fn kind(&self) -> PayloadTransportKind {
        // Uses RelayHop as placeholder until PayloadTransportKind::Tor is added
        PayloadTransportKind::RelayHop
    }

    async fn fetch_share(
        &self,
        peer_addr: &str,
        _mid_digest: [u8; 32],
        _slot_index: u16,
        _segment_index: u32,
    ) -> Result<Option<crate::share::MiasmaShare>, PayloadTransportError> {
        match &self.mode {
            TorMode::External { socks_addr } => {
                // When integrated:
                // 1. Connect to Tor SOCKS5 proxy
                // 2. Request connection to peer_addr through Tor
                // 3. Send ShareFetchRequest over the anonymized stream
                // 4. Read ShareFetchResponse
                Err(PayloadTransportError {
                    phase: TransportPhase::Session,
                    message: format!(
                        "Tor (external SOCKS5 at {socks_addr}) to {peer_addr}: \
                         not yet connected (integration pending)"
                    ),
                })
            }
            TorMode::Embedded => {
                // When Arti is integrated:
                // 1. Bootstrap TorClient (lazy, first use)
                // 2. client.connect((peer_host, peer_port))
                // 3. Run share-fetch protocol over anonymized stream
                Err(PayloadTransportError {
                    phase: TransportPhase::Session,
                    message: format!(
                        "Tor (embedded Arti) to {peer_addr}: \
                         requires 'tor' crate feature (arti-client)"
                    ),
                })
            }
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default() {
        let c = TorConfig::default();
        assert!(!c.enabled);
        assert!(!c.is_configured());
    }

    #[test]
    fn config_external_mode() {
        let c = TorConfig {
            enabled: true,
            use_embedded: false,
            socks_port: 9050,
            ..Default::default()
        };
        assert!(c.is_configured());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_embedded_mode() {
        let c = TorConfig {
            enabled: true,
            use_embedded: true,
            ..Default::default()
        };
        assert!(c.is_configured());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_with_bridges() {
        let c = TorConfig {
            enabled: true,
            use_embedded: true,
            bridges: vec![
                "obfs4 1.2.3.4:443 cert=... iat-mode=0".to_string(),
                "obfs4 5.6.7.8:443 cert=... iat-mode=0".to_string(),
            ],
            ..Default::default()
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_empty_bridge_rejected() {
        let c = TorConfig {
            enabled: true,
            bridges: vec!["".to_string()],
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_zero_socks_port_rejected() {
        let c = TorConfig {
            enabled: true,
            use_embedded: false,
            socks_port: 0,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_disabled_skips_validation() {
        let c = TorConfig {
            enabled: false,
            socks_port: 0,
            ..Default::default()
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn config_serde() {
        let c = TorConfig {
            enabled: true,
            use_embedded: true,
            socks_port: 9050,
            bridges: vec!["obfs4 1.2.3.4:443".to_string()],
            circuit_timeout_secs: 45,
            state_dir: Some("/tmp/tor".to_string()),
        };
        let json = serde_json::to_string(&c).unwrap();
        let de: TorConfig = serde_json::from_str(&json).unwrap();
        assert!(de.enabled);
        assert!(de.use_embedded);
        assert_eq!(de.bridges.len(), 1);
    }

    #[test]
    fn transport_external_mode() {
        let c = TorConfig {
            enabled: true,
            use_embedded: false,
            socks_port: 9050,
            ..Default::default()
        };
        let t = TorPayloadTransport::new(c).unwrap();
        assert_eq!(t.mode_name(), "external-socks5");
        assert!(!t.has_bridges());
    }

    #[test]
    fn transport_embedded_mode() {
        let c = TorConfig {
            enabled: true,
            use_embedded: true,
            bridges: vec!["bridge line".to_string()],
            ..Default::default()
        };
        let t = TorPayloadTransport::new(c).unwrap();
        assert_eq!(t.mode_name(), "embedded-arti");
        assert!(t.has_bridges());
    }

    #[test]
    fn state_dir_default() {
        let c = TorConfig::default();
        let dir = c.state_dir(std::path::Path::new("/data"));
        assert!(dir.to_string_lossy().contains("tor"));
    }

    #[tokio::test]
    async fn transport_external_returns_error() {
        let c = TorConfig {
            enabled: true,
            use_embedded: false,
            socks_port: 9050,
            ..Default::default()
        };
        let t = TorPayloadTransport::new(c).unwrap();
        use super::super::payload::PayloadTransport;
        let result = t.fetch_share("peer:9000", [0u8; 32], 0, 0).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("SOCKS5"));
    }

    #[tokio::test]
    async fn transport_embedded_returns_error() {
        let c = TorConfig {
            enabled: true,
            use_embedded: true,
            ..Default::default()
        };
        let t = TorPayloadTransport::new(c).unwrap();
        use super::super::payload::PayloadTransport;
        let result = t.fetch_share("peer:9000", [0u8; 32], 0, 0).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("Arti"));
    }
}
