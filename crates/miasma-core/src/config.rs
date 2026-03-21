/// Node configuration — persisted to `{data_dir}/config.toml`.
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::MiasmaError;

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// QUIC listen multiaddr.
    pub listen_addr: String,
    /// Bootstrap peer multiaddrs.
    pub bootstrap_peers: Vec<String>,
}

/// Transport-layer configuration for restrictive networks.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            quota_mb: 10_240,    // 10 GiB desktop default
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

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            storage: StorageConfig::default(),
            network: NetworkConfig::default(),
            transport: TransportConfig::default(),
        }
    }
}

impl NodeConfig {
    pub fn load(data_dir: &Path) -> Result<Self, MiasmaError> {
        let path = data_dir.join("config.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)?;
        toml::from_str(&raw).map_err(|e| MiasmaError::Serialization(e.to_string()))
    }

    pub fn save(&self, data_dir: &Path) -> Result<(), MiasmaError> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join("config.toml");
        let raw = toml::to_string_pretty(self)
            .map_err(|e| MiasmaError::Serialization(e.to_string()))?;
        std::fs::write(&path, raw)?;

        // If proxy credentials are present, restrict config.toml permissions
        // to prevent co-resident users from reading plaintext credentials.
        if self.transport.proxy_username.is_some() || self.transport.proxy_password.is_some() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            #[cfg(windows)]
            {
                if let Ok(username) = std::env::var("USERNAME") {
                    let path_str = path.display().to_string();
                    let _ = std::process::Command::new("icacls")
                        .args([&path_str, "/inheritance:r", "/grant:r", &format!("{username}:F")])
                        .output();
                }
            }
        }
        Ok(())
    }

    /// Scrub credential fields (proxy username/password) from this config,
    /// then save the scrubbed version back to disk.
    pub fn scrub_credentials(&mut self, data_dir: &Path) -> Result<(), MiasmaError> {
        self.transport.proxy_username = None;
        self.transport.proxy_password = None;
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
