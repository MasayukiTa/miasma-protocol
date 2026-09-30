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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Maximum storage for held shares, in MiB.
    pub quota_mb: u64,
    /// Maximum outbound bandwidth for share serving, in MiB/day.
    pub bandwidth_mb_day: u64,
    /// Maximum storage for shares pushed to this node by *other* publishers
    /// (hosted shares), in MiB. Separate from `quota_mb`, which bounds the
    /// node's own published shares.
    ///
    /// **Default 0 = this node refuses every pushed share.** That is
    /// deliberate: accepting other peoples' shares by default lets any peer
    /// fill the disk, so hosting is opt-in. Set it on a helper node (e.g.
    /// `miasma config --key storage.hosted_quota_mb --value 2048`) to let it
    /// hold shares for a publisher that may go offline. Takes effect when the
    /// daemon starts. There is no eviction and no per-peer limit yet: once the
    /// quota is full, further pushes are refused.
    #[serde(default)]
    pub hosted_quota_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// QUIC listen multiaddr.
    pub listen_addr: String,
    /// Bootstrap peer multiaddrs.
    pub bootstrap_peers: Vec<String>,
}

/// Transport-layer configuration for restrictive networks.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TransportConfig {
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

impl fmt::Debug for TransportConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportConfig")
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
            bandwidth_mb_day: 1_024,
            hosted_quota_mb: 0, // opt-in; see the field's doc comment
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
/// - Linux/macOS: `~/.local/share/miasma`
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
