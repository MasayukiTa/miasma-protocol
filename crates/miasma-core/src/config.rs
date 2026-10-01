/// Node configuration — persisted to `{data_dir}/config.toml`.
use std::{
    fmt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::MiasmaError;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeConfig {
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub transport: TransportConfig,
}

pub const DEFAULT_HOSTED_QUOTA_MB: u64 = 1_024;

fn default_hosted_quota_mb() -> u64 {
    DEFAULT_HOSTED_QUOTA_MB
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Maximum storage for held shares, in MiB.
    pub quota_mb: u64,
    /// Maximum storage for shares hosted on behalf of remote publishers, in MiB.
    /// Kept separate from the node's owned-share quota so remote traffic cannot
    /// evict locally published shares.
    ///
    /// Defaults to `DEFAULT_HOSTED_QUOTA_MB` (also for a `config.toml` written
    /// before the key existed) so the shipped node takes part in distributed
    /// hosting. It is a hard cap, not an opt-in switch: set
    /// `miasma config --key storage.hosted_quota_mb --value 0` to refuse every
    /// pushed share, or a larger value on a helper node. Takes effect when the
    /// daemon starts. There is no eviction and no per-peer limit yet: once the
    /// quota is full, further pushes are refused.
    #[serde(default = "default_hosted_quota_mb")]
    pub hosted_quota_mb: u64,
    /// Maximum outbound bandwidth for share serving, in MiB/day.
    pub bandwidth_mb_day: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// QUIC listen multiaddr.
    pub listen_addr: String,
    /// Bootstrap peer multiaddrs.
    pub bootstrap_peers: Vec<String>,
}

/// How the iroh direct transport (receive by share ID alone) is set up.
///
/// * `n0`: the default. Number 0's public relays and its discovery service
///   (DNS/pkarr) are used, so a receiver finds the sender from the share ID
///   alone. The sender's endpoint ID, home relay and IP addresses are published
///   to n0's discovery service while the daemon runs; see SECURITY.md.
/// * `custom`: only the relays in `iroh_relay_urls` (your own), nothing of n0's
///   unless `iroh_discovery` is on.
/// * `off`: no iroh endpoint is started and none is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IrohMode {
    #[default]
    N0,
    Custom,
    Off,
}

impl IrohMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::N0 => "n0",
            Self::Custom => "custom",
            Self::Off => "off",
        }
    }
}

impl std::str::FromStr for IrohMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "n0" => Ok(Self::N0),
            "custom" => Ok(Self::Custom),
            "off" => Ok(Self::Off),
            other => Err(format!(
                "unknown iroh mode '{other}': expected n0, custom or off"
            )),
        }
    }
}

impl fmt::Display for IrohMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn default_true() -> bool {
    true
}

/// Seconds a receive waits to reach a sender over iroh before it tries the next
/// source.
pub const DEFAULT_IROH_CONNECT_TIMEOUT_SECS: u64 = 25;

fn default_iroh_connect_timeout_secs() -> u64 {
    DEFAULT_IROH_CONNECT_TIMEOUT_SECS
}

/// Transport-layer configuration for restrictive networks.
#[derive(Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// iroh direct transport: `n0` (default), `custom` or `off`. See
    /// [`IrohMode`]. Takes effect when the daemon starts.
    #[serde(default)]
    pub iroh_mode: IrohMode,
    /// Relay URLs (`https://...`) for `custom` mode, and extra relay hints for
    /// dialing in every mode.
    #[serde(default)]
    pub iroh_relay_urls: Vec<String>,
    /// Publish this node's address to, and look senders up in, n0's discovery
    /// service (`n0` mode always; `custom` mode if true). With it off a receiver
    /// can only reach senders through `iroh_relay_urls`.
    #[serde(default = "default_true")]
    pub iroh_discovery: bool,
    /// Announce this node on, and look senders up in, the local network (mDNS),
    /// so two machines on one LAN connect without the internet. The announcement
    /// carries the endpoint ID and the LAN addresses and is visible to the whole
    /// LAN; turn it off on a network you do not trust.
    #[serde(default = "default_true")]
    pub iroh_lan_discovery: bool,
    /// How long one receive tries to reach a sender over iroh, in seconds.
    #[serde(default = "default_iroh_connect_timeout_secs")]
    pub iroh_connect_timeout_secs: u64,
    /// Port for the WebSocket share server, on 127.0.0.1. `0` (the default)
    /// picks a free port each start. Set a fixed port to expose the server
    /// through an outbound tunnel, e.g. `cloudflared tunnel --url
    /// http://127.0.0.1:<port>`; the tunnel terminates TLS, so leave
    /// `wss_tls_enabled` off for that use.
    #[serde(default)]
    pub wss_port: u16,
    /// Enable TLS on the WSS share server and client connections.
    #[serde(default)]
    pub wss_tls_enabled: bool,
    /// SNI hostname for WSS TLS (should look like a CDN domain).
    #[serde(default)]
    pub wss_sni: Option<String>,
    /// Path to PEM-encoded server certificate for WSS TLS.
    #[serde(default)]
    pub wss_cert_pem_path: Option<String>,
    /// Path to PEM-encoded server private key for WSS TLS.
    #[serde(default)]
    pub wss_key_pem_path: Option<String>,
    /// Outbound proxy type: "socks5" or "http-connect".
    #[serde(default)]
    pub proxy_type: Option<String>,
    /// Outbound proxy address (e.g. "127.0.0.1:1080").
    #[serde(default)]
    pub proxy_addr: Option<String>,
    /// Proxy username (optional).
    #[serde(default)]
    pub proxy_username: Option<String>,
    /// Proxy password (optional).
    #[serde(default)]
    pub proxy_password: Option<String>,
    /// Enable ObfuscatedQuic REALITY transport.
    #[serde(default)]
    pub obfuscated_quic_enabled: bool,
    /// SNI for ObfuscatedQuic (e.g. "cdn.cloudflare.com").
    #[serde(default)]
    pub obfuscated_quic_sni: Option<String>,
    /// Hex-encoded 32-byte probe secret for ObfuscatedQuic.
    #[serde(default)]
    pub obfuscated_quic_secret: Option<String>,
    /// Fallback URL for ObfuscatedQuic active-probe resistance.
    #[serde(default)]
    pub obfuscated_quic_fallback_url: Option<String>,

    // ── Shadowsocks (bridge superhardening Phase 3) ─────────────────────
    /// Shadowsocks transport configuration.
    #[serde(default)]
    pub shadowsocks: crate::transport::shadowsocks::ShadowsocksConfig,

    // ── Tor (bridge superhardening Phase 4) ─────────────────────────────
    /// Tor transport configuration.
    #[serde(default)]
    pub tor: crate::transport::tor::TorConfig,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            iroh_mode: IrohMode::default(),
            iroh_relay_urls: Vec::new(),
            iroh_discovery: true,
            iroh_lan_discovery: true,
            iroh_connect_timeout_secs: DEFAULT_IROH_CONNECT_TIMEOUT_SECS,
            wss_port: 0,
            wss_tls_enabled: false,
            wss_sni: None,
            wss_cert_pem_path: None,
            wss_key_pem_path: None,
            proxy_type: None,
            proxy_addr: None,
            proxy_username: None,
            proxy_password: None,
            obfuscated_quic_enabled: false,
            obfuscated_quic_sni: None,
            obfuscated_quic_secret: None,
            obfuscated_quic_fallback_url: None,
            shadowsocks: Default::default(),
            tor: Default::default(),
        }
    }
}

impl fmt::Debug for TransportConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportConfig")
            .field("iroh_mode", &self.iroh_mode)
            .field("iroh_relay_urls", &self.iroh_relay_urls)
            .field("iroh_discovery", &self.iroh_discovery)
            .field("iroh_lan_discovery", &self.iroh_lan_discovery)
            .field("iroh_connect_timeout_secs", &self.iroh_connect_timeout_secs)
            .field("wss_port", &self.wss_port)
            .field("wss_tls_enabled", &self.wss_tls_enabled)
            .field("wss_sni", &self.wss_sni)
            .field("wss_cert_pem_path", &self.wss_cert_pem_path)
            .field("wss_key_pem_path", &self.wss_key_pem_path)
            .field("proxy_type", &self.proxy_type)
            .field("proxy_addr", &self.proxy_addr)
            .field("proxy_username_configured", &self.proxy_username.is_some())
            .field("proxy_password_configured", &self.proxy_password.is_some())
            .field("obfuscated_quic_enabled", &self.obfuscated_quic_enabled)
            .field("obfuscated_quic_sni", &self.obfuscated_quic_sni)
            .field(
                "obfuscated_quic_secret_configured",
                &self.obfuscated_quic_secret.is_some(),
            )
            .field(
                "obfuscated_quic_fallback_url",
                &self.obfuscated_quic_fallback_url,
            )
            .field("shadowsocks", &self.shadowsocks)
            .field("tor", &self.tor)
            .finish()
    }
}

impl TransportConfig {
    /// Parse the ObfuscatedQuic probe secret using the same fail-closed rules
    /// everywhere. Disabled transport returns `Ok(None)` without interpreting a
    /// stale configured value.
    pub fn parsed_obfuscated_quic_secret(&self) -> Result<Option<Zeroizing<[u8; 32]>>, String> {
        if !self.obfuscated_quic_enabled {
            return Ok(None);
        }
        let hex_secret = self
            .obfuscated_quic_secret
            .as_deref()
            .ok_or_else(|| "ObfuscatedQuic enabled but probe secret is missing".to_string())?;
        let decoded = Zeroizing::new(
            hex::decode(hex_secret)
                .map_err(|_| "ObfuscatedQuic probe secret must be valid hex".to_string())?,
        );
        if decoded.len() != 32 {
            return Err("ObfuscatedQuic probe secret must be exactly 32 bytes".into());
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&decoded);
        if secret.iter().all(|byte| *byte == 0) {
            return Err("ObfuscatedQuic probe secret must not be all-zero".into());
        }
        Ok(Some(secret))
    }

    fn zeroize_option_string(value: &mut Option<String>) -> bool {
        if let Some(mut secret) = value.take() {
            secret.zeroize();
            true
        } else {
            false
        }
    }

    /// Erase secret String copies held by this in-memory transport config without
    /// changing enablement semantics. Call only after runtime key material has
    /// been extracted into dedicated zeroizing state.
    pub fn zeroize_secret_copies(&mut self) {
        Self::zeroize_option_string(&mut self.proxy_username);
        Self::zeroize_option_string(&mut self.proxy_password);
        Self::zeroize_option_string(&mut self.obfuscated_quic_secret);
        Self::zeroize_option_string(&mut self.shadowsocks.password);
    }
}

impl Drop for TransportConfig {
    fn drop(&mut self) {
        self.zeroize_secret_copies();
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            quota_mb: 10_240, // 10 GiB desktop default
            hosted_quota_mb: DEFAULT_HOSTED_QUOTA_MB,
            bandwidth_mb_day: 1_024,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/udp/0/quic-v1".into(),
            bootstrap_peers: vec![],
        }
    }
}

impl NodeConfig {
    pub fn load(data_dir: &Path) -> Result<Self, MiasmaError> {
        let path = data_dir.join("config.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = Zeroizing::new(std::fs::read_to_string(&path)?);
        toml::from_str(raw.as_str()).map_err(|e| MiasmaError::Serialization(e.to_string()))
    }

    pub fn save(&self, data_dir: &Path) -> Result<(), MiasmaError> {
        self.transport
            .parsed_obfuscated_quic_secret()
            .map_err(|e| MiasmaError::Serialization(format!("invalid transport config: {e}")))?;
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join("config.toml");
        let raw = Zeroizing::new(
            toml::to_string_pretty(self).map_err(|e| MiasmaError::Serialization(e.to_string()))?,
        );

        // If persisted transport secrets are present, write with restricted
        // permissions from the start (Win32 DACL / Unix 0o600). If we're
        // rewriting an already-restricted config after scrubbing secrets, keep
        // using the restricted writer so Windows can safely replace it.
        let has_secrets = self.has_persisted_secrets();
        let was_restricted = if path.exists() {
            crate::secure_file::verify_restricted(&path).unwrap_or(false)
        } else {
            false
        };

        if has_secrets || was_restricted {
            crate::secure_file::write_restricted(&path, raw.as_bytes())?;
        } else {
            std::fs::write(&path, raw)?;
        }
        Ok(())
    }

    /// Whether `config.toml` currently contains persisted secret material.
    /// Paths to externally managed key files are not counted here because the
    /// path itself is not the key material and may point outside the data dir.
    pub fn has_persisted_secrets(&self) -> bool {
        self.transport.proxy_username.is_some()
            || self.transport.proxy_password.is_some()
            || self.transport.obfuscated_quic_secret.is_some()
            || self.transport.shadowsocks.password.is_some()
    }

    /// Scrub persisted transport credentials/secrets from this config, then save
    /// the sanitized version back to disk.
    pub fn scrub_credentials(&mut self, data_dir: &Path) -> Result<(), MiasmaError> {
        TransportConfig::zeroize_option_string(&mut self.transport.proxy_username);
        TransportConfig::zeroize_option_string(&mut self.transport.proxy_password);
        if TransportConfig::zeroize_option_string(&mut self.transport.obfuscated_quic_secret) {
            self.transport.obfuscated_quic_enabled = false;
        }
        let shadowsocks_secret_removed =
            TransportConfig::zeroize_option_string(&mut self.transport.shadowsocks.password);
        if shadowsocks_secret_removed && self.transport.shadowsocks.server.is_some() {
            // Native Shadowsocks cannot operate after its PSK is destroyed.
            self.transport.shadowsocks.enabled = false;
        }
        self.save(data_dir)
    }
}

/// Return the default Miasma data directory.
///
/// - Linux:       `~/.local/share/miasma`
/// - macOS:       `~/Library/Application Support/miasma`
/// - Windows:     `%APPDATA%\miasma`
pub fn default_data_dir() -> PathBuf {
    directories::ProjectDirs::from("", "", "miasma")
        .map(|d| d.data_local_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".miasma"))
}

/// Stamp the data directory with the running binary version.
///
/// Written on every startup to support future upgrade detection.
/// The file is a simple text file containing the version string.
pub fn stamp_version(data_dir: &Path, version: &str) {
    let path = data_dir.join("version");
    let _ = std::fs::write(path, version);
}

/// Read the last-stamped version from the data directory.
pub fn read_stamped_version(data_dir: &Path) -> Option<String> {
    std::fs::read_to_string(data_dir.join("version"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod debug_redaction_tests {
    use super::*;

    #[test]
    fn storage_config_defaults_to_positive_hosted_quota() {
        let storage = StorageConfig::default();
        assert_eq!(storage.hosted_quota_mb, DEFAULT_HOSTED_QUOTA_MB);
        assert!(storage.hosted_quota_mb > 0);
    }

    #[test]
    fn legacy_storage_config_gets_hosted_quota_default() {
        let storage: StorageConfig = toml::from_str(
            "quota_mb = 2048
bandwidth_mb_day = 512
",
        )
        .unwrap();
        assert_eq!(storage.quota_mb, 2_048);
        assert_eq!(storage.bandwidth_mb_day, 512);
        assert_eq!(storage.hosted_quota_mb, DEFAULT_HOSTED_QUOTA_MB);
    }

    #[test]
    fn an_old_config_without_iroh_keys_gets_the_defaults() {
        let t: TransportConfig = toml::from_str("wss_port = 7\n").unwrap();
        assert_eq!(t.wss_port, 7);
        assert_eq!(t.iroh_mode, IrohMode::N0);
        assert!(t.iroh_relay_urls.is_empty());
        assert!(t.iroh_discovery);
        assert!(t.iroh_lan_discovery);
        assert_eq!(
            t.iroh_connect_timeout_secs,
            DEFAULT_IROH_CONNECT_TIMEOUT_SECS
        );
        let d = TransportConfig::default();
        assert_eq!(d.iroh_mode, IrohMode::N0);
        assert!(d.iroh_discovery);
    }

    #[test]
    fn iroh_mode_parses_and_round_trips_through_toml() {
        assert_eq!("off".parse::<IrohMode>().unwrap(), IrohMode::Off);
        assert_eq!(" Custom ".parse::<IrohMode>().unwrap(), IrohMode::Custom);
        assert!("everything".parse::<IrohMode>().is_err());
        let t: TransportConfig = toml::from_str("iroh_mode = \"off\"\n").unwrap();
        assert_eq!(t.iroh_mode, IrohMode::Off);
        let text = toml::to_string_pretty(&t).unwrap();
        assert!(text.contains("iroh_mode = \"off\""), "{text}");
    }

    #[test]
    fn transport_config_debug_redacts_secrets() {
        let mut cfg = TransportConfig::default();
        cfg.proxy_username = Some("debug-user-value".into());
        cfg.proxy_password = Some("debug-password-value".into());
        cfg.obfuscated_quic_secret = Some("debug-probe-value".into());
        cfg.shadowsocks.password = Some("debug-shadow-value".into());
        let rendered = format!("{cfg:?}");
        for value in [
            "debug-user-value",
            "debug-password-value",
            "debug-probe-value",
            "debug-shadow-value",
        ] {
            assert!(!rendered.contains(value));
        }
        assert!(rendered.contains("proxy_password_configured: true"));
        assert!(rendered.contains("obfuscated_quic_secret_configured: true"));
    }
}
