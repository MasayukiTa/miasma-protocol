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
        std::fs::write(path, raw)?;
        Ok(())
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
