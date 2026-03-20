/// librqbit-backed torrent engine for the Miasma bridge.
///
/// Wraps `librqbit::Session` to provide:
/// - Download from existing BT swarms (magnet URI or .torrent file)
/// - Optional seeding (default off)
/// - SOCKS5 proxy passthrough for DPI resistance
/// - Progress callbacks for CLI/daemon integration
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use librqbit::{
    AddTorrent, AddTorrentOptions, AddTorrentResponse, ManagedTorrent, Session, SessionOptions,
};
use tracing::{debug, info};

// ─── Configuration ──────────────────────────────────────────────────────────

/// Configuration for the torrent engine.
#[derive(Debug, Clone)]
pub struct TorrentConfig {
    /// Directory for downloaded torrent data.
    pub output_dir: PathBuf,
    /// Enable seeding after download completes. Default: false.
    pub seed_enabled: bool,
    /// Upload rate limit in bits/sec. 0 = unlimited. Only effective if seed_enabled.
    pub upload_rate_limit_bps: u32,
    /// Download rate limit in bits/sec. 0 = unlimited.
    pub download_rate_limit_bps: u32,
    /// SOCKS5 proxy URL for all BT connections (e.g. "socks5://127.0.0.1:1080").
    pub proxy_url: Option<String>,
    /// Maximum total bytes to download. 0 = unlimited.
    pub max_total_bytes: u64,
    /// Disable DHT. Default: false.
    pub disable_dht: bool,
    /// Disable HTTP trackers. Default: false.
    pub disable_trackers: bool,
}

impl Default for TorrentConfig {
    fn default() -> Self {
        Self {
            output_dir: std::env::temp_dir().join("miasma-bridge-downloads"),
            seed_enabled: false,
            upload_rate_limit_bps: 0,
            download_rate_limit_bps: 0,
            proxy_url: None,
            max_total_bytes: 0,
            disable_dht: false,
            disable_trackers: false,
        }
    }
}

// ─── Download result ────────────────────────────────────────────────────────

/// A single downloaded file from a torrent.
#[derive(Debug)]
pub struct DownloadedFile {
    /// Relative path within the torrent (e.g. "folder/file.txt").
    pub path: String,
    /// File size in bytes.
    pub size: u64,
    /// Absolute path to the downloaded file on disk.
    pub disk_path: PathBuf,
}

/// Result of a torrent download operation.
#[derive(Debug)]
pub struct TorrentDownloadResult {
    /// Info-hash hex string.
    pub info_hash_hex: String,
    /// Display name of the torrent.
    pub name: String,
    /// Downloaded files.
    pub files: Vec<DownloadedFile>,
    /// Total bytes downloaded.
    pub total_bytes: u64,
}

// ─── Progress callback ──────────────────────────────────────────────────────

/// Progress information passed to the callback.
#[derive(Debug, Clone)]
pub struct DownloadProgress {
    /// Bytes downloaded so far.
    pub downloaded_bytes: u64,
    /// Total bytes in the torrent.
    pub total_bytes: u64,
    /// Number of connected peers.
    pub peers: usize,
    /// Download speed in Mbps (approximate).
    pub download_speed_mbps: f64,
    /// Whether download is complete.
    pub finished: bool,
}

// ─── Session wrapper ────────────────────────────────────────────────────────

/// Wraps a librqbit Session for Miasma bridge use.
pub struct MiasmaSession {
    session: Arc<Session>,
    config: TorrentConfig,
}

impl MiasmaSession {
    /// Create a new session with the given configuration.
    pub async fn new(config: TorrentConfig) -> Result<Self> {
        // Ensure output directory exists.
        tokio::fs::create_dir_all(&config.output_dir)
            .await
            .context("creating torrent output directory")?;

        let mut opts = SessionOptions::default();
        opts.disable_dht = config.disable_dht;
        opts.disable_dht_persistence = true; // bridge sessions are ephemeral

        // Proxy configuration.
        if let Some(ref proxy) = config.proxy_url {
            info!(proxy = %proxy, "BT connections routed through proxy");
            opts.socks_proxy_url = Some(proxy.clone());
        }

        // Rate limits.
        let upload_limit = if config.seed_enabled && config.upload_rate_limit_bps > 0 {
            std::num::NonZeroU32::new(config.upload_rate_limit_bps)
        } else if !config.seed_enabled {
            // Effectively disable upload by setting 1 bps.
            std::num::NonZeroU32::new(1)
        } else {
            None
        };
        let download_limit = std::num::NonZeroU32::new(config.download_rate_limit_bps);

        opts.ratelimits = librqbit::limits::LimitsConfig {
            upload_bps: upload_limit,
            download_bps: download_limit,
        };

        let session = Session::new_with_opts(config.output_dir.clone(), opts)
            .await
            .context("creating librqbit session")?;

        Ok(Self { session, config })
    }

    /// Download a torrent from a magnet URI.
    pub async fn download_magnet<F>(
        &self,
        magnet_uri: &str,
        progress_fn: Option<F>,
    ) -> Result<TorrentDownloadResult>
    where
        F: Fn(DownloadProgress) + Send + 'static,
    {
        info!(magnet = %magnet_uri, "Adding torrent from magnet");

        let add_opts = AddTorrentOptions {
            overwrite: true,
            disable_trackers: self.config.disable_trackers,
            ..Default::default()
        };

        let resp = self
            .session
            .add_torrent(AddTorrent::from_url(magnet_uri), Some(add_opts))
            .await
            .context("adding torrent from magnet")?;

        self.wait_for_download(resp, progress_fn).await
    }

    /// Download a torrent from a .torrent file path.
    pub async fn download_torrent_file<F>(
        &self,
        torrent_path: &Path,
        progress_fn: Option<F>,
    ) -> Result<TorrentDownloadResult>
    where
        F: Fn(DownloadProgress) + Send + 'static,
    {
        info!(path = %torrent_path.display(), "Adding torrent from file");

        let torrent_bytes = tokio::fs::read(torrent_path)
            .await
            .context("reading .torrent file")?;

        let add_opts = AddTorrentOptions {
            overwrite: true,
            disable_trackers: self.config.disable_trackers,
            ..Default::default()
        };

        let resp = self
            .session
            .add_torrent(AddTorrent::from_bytes(torrent_bytes), Some(add_opts))
            .await
            .context("adding torrent from file")?;

        self.wait_for_download(resp, progress_fn).await
    }

    /// Wait for a torrent download to complete.
    async fn wait_for_download<F>(
        &self,
        resp: AddTorrentResponse,
        progress_fn: Option<F>,
    ) -> Result<TorrentDownloadResult>
    where
        F: Fn(DownloadProgress) + Send + 'static,
    {
        let handle: Arc<ManagedTorrent> = resp
            .into_handle()
            .ok_or_else(|| anyhow::anyhow!("no torrent handle returned"))?;

        let info_hash_hex = hex::encode(handle.info_hash().0);
        let name = handle.name().unwrap_or_else(|| "unknown".into());

        info!(hash = %info_hash_hex, name = %name, "Torrent added, waiting for download");

        // Wait for metadata (magnet URIs need to resolve first).
        handle
            .wait_until_initialized()
            .await
            .context("waiting for torrent metadata")?;

        // Safety check: total size.
        if self.config.max_total_bytes > 0 {
            let total = handle.stats().total_bytes;
            if total > self.config.max_total_bytes {
                bail!(
                    "Torrent too large: {} bytes > max {} bytes",
                    total,
                    self.config.max_total_bytes
                );
            }
        }

        // Progress monitoring loop.
        let progress_handle = handle.clone();
        let progress_task = if let Some(cb) = progress_fn {
            Some(tokio::spawn(async move {
                loop {
                    let stats = progress_handle.stats();
                    let live = stats.live.as_ref();
                    let progress = DownloadProgress {
                        downloaded_bytes: stats.progress_bytes,
                        total_bytes: stats.total_bytes,
                        peers: live.map_or(0, |l| l.snapshot.peer_stats.live as usize),
                        download_speed_mbps: live.map_or(0.0, |l| l.download_speed.mbps),
                        finished: stats.finished,
                    };
                    cb(progress.clone());
                    if progress.finished {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }))
        } else {
            None
        };

        // Wait for download completion.
        handle
            .wait_until_completed()
            .await
            .context("waiting for torrent download")?;

        // Cancel progress task.
        if let Some(task) = progress_task {
            task.abort();
        }

        info!(hash = %info_hash_hex, "Torrent download complete");

        // Collect downloaded files.
        let mut files = Vec::new();
        let mut total_bytes = 0u64;

        let file_result = handle.with_metadata(|meta| {
            let mut result = Vec::new();
            for fi in &meta.file_infos {
                let rel_path = fi.relative_filename.to_string_lossy().to_string();
                let disk_path = self.config.output_dir.join(&rel_path);
                total_bytes += fi.len;
                result.push(DownloadedFile {
                    path: rel_path,
                    size: fi.len,
                    disk_path,
                });
            }
            result
        });

        if let Ok(f) = file_result {
            files = f;
        }

        // If seeding is not enabled, pause the torrent.
        if !self.config.seed_enabled {
            debug!("Seeding disabled, pausing torrent");
            let _ = self.session.pause(&handle).await;
        }

        Ok(TorrentDownloadResult {
            info_hash_hex,
            name,
            files,
            total_bytes,
        })
    }

    /// Shut down the session gracefully.
    pub async fn shutdown(self) {
        self.session.stop().await;
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_seed_disabled() {
        let cfg = TorrentConfig::default();
        assert!(!cfg.seed_enabled);
        assert!(cfg.proxy_url.is_none());
        assert_eq!(cfg.max_total_bytes, 0);
    }

    #[test]
    fn config_with_proxy() {
        let cfg = TorrentConfig {
            proxy_url: Some("socks5://127.0.0.1:9050".into()),
            seed_enabled: true,
            upload_rate_limit_bps: 100_000,
            ..Default::default()
        };
        assert!(cfg.seed_enabled);
        assert_eq!(cfg.proxy_url.as_deref(), Some("socks5://127.0.0.1:9050"));
    }
}
