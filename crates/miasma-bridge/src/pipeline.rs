#![allow(dead_code)]

/// Magnet link → Miasma MID conversion pipeline — Phase 2 (Task 15).
///
/// # Flow
/// ```text
/// magnet:?xt=urn:btih:<info_hash>&dn=<name>&...
///    │
///    ▼
/// MagnetInfo { info_hash, display_name }
///    │
///    │  [fetch torrent metadata via BT DHT — Phase 2: librqbit]
///    ▼
/// TorrentMeta { files: Vec<FileEntry> }
///    │
///    │  for each file: download & dissolve into Miasma
///    ▼
/// BridgeResult { info_hash, mids: Vec<String> }
///    │
///    │  insert all (info_hash, mid) pairs into BtMiasmaIndex
///    ▼
/// Done
/// ```
///
/// # Privacy protections
/// - Dissolution of each file is issued in random order.
/// - A configurable random delay (`batch_delay`) is inserted between files
///   so that burst I/O cannot correlate files to a single torrent.
/// - The reverse BT → MID mapping is only published if the user opts in.
///
/// # Phase 2 integration plan
/// 1. Add `librqbit` dependency in Cargo.toml.
/// 2. Replace `fetch_torrent_metadata` stub with a real `librqbit` session.
/// 3. Stream each file directly into `miasma-core::dissolve_file` so that
///   large files never fully land on disk.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("Invalid magnet link: {0}")]
    InvalidMagnet(String),
    #[error("BT metadata fetch failed: {0}")]
    MetadataFetch(String),
    #[error("Dissolution failed: {0}")]
    Dissolution(String),
    #[error("Index error: {0}")]
    Index(String),
}

// ─── Magnet link parsing ──────────────────────────────────────────────────────

/// Parsed fields from a magnet URI.
#[derive(Debug, Clone)]
pub struct MagnetInfo {
    /// BitTorrent info-hash (20 bytes).
    pub info_hash: [u8; 20],
    /// Optional display name from `dn=` parameter.
    pub display_name: Option<String>,
}

impl MagnetInfo {
    /// Parse a magnet URI (`magnet:?xt=urn:btih:<hex_or_base32>&…`).
    pub fn parse(magnet: &str) -> Result<Self, PipelineError> {
        let uri = magnet.trim();
        if !uri.starts_with("magnet:?") {
            return Err(PipelineError::InvalidMagnet(
                "URI does not start with 'magnet:?'".into(),
            ));
        }

        let params = &uri["magnet:?".len()..];
        let mut info_hash_bytes: Option<[u8; 20]> = None;
        let mut display_name: Option<String> = None;

        for kv in params.split('&') {
            if let Some(xt) = kv.strip_prefix("xt=urn:btih:") {
                let decoded = decode_info_hash(xt)
                    .map_err(|e| PipelineError::InvalidMagnet(e))?;
                info_hash_bytes = Some(decoded);
            } else if let Some(dn) = kv.strip_prefix("dn=") {
                display_name = Some(url_decode(dn));
            }
        }

        let info_hash = info_hash_bytes
            .ok_or_else(|| PipelineError::InvalidMagnet("missing xt=urn:btih: field".into()))?;

        Ok(Self { info_hash, display_name })
    }
}

fn decode_info_hash(s: &str) -> Result<[u8; 20], String> {
    if s.len() == 40 {
        // Hex
        let bytes = hex::decode(s).map_err(|e| format!("hex decode: {e}"))?;
        bytes.try_into().map_err(|_| "expected 20 bytes".into())
    } else if s.len() == 32 {
        // Base32 (without padding)
        // Phase 2: use a proper base32 crate; stub here
        Err("Base32 info-hash parsing not yet implemented (Phase 2)".into())
    } else {
        Err(format!("unexpected info-hash length: {}", s.len()))
    }
}

fn url_decode(s: &str) -> String {
    s.replace('+', " ")
        .replace("%20", " ")
        .replace("%2B", "+")
        .replace("%2F", "/")
}

// ─── Bridge result ────────────────────────────────────────────────────────────

/// Result of bridging a single torrent to Miasma.
#[derive(Debug, Clone)]
pub struct BridgeResult {
    pub info_hash: [u8; 20],
    /// MIDs produced, one per file in the torrent.
    pub mids: Vec<String>,
}

// ─── Pipeline configuration ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BridgePipelineConfig {
    /// Random delay range between file dissolutions (privacy: prevents burst
    /// correlation). Values in ms.
    pub batch_delay_min_ms: u64,
    pub batch_delay_max_ms: u64,
    /// Publish the reverse MID → info_hash mapping.
    pub reverse_lookup_enabled: bool,
}

impl Default for BridgePipelineConfig {
    fn default() -> Self {
        Self {
            batch_delay_min_ms: 500,
            batch_delay_max_ms: 5_000,
            reverse_lookup_enabled: false,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_magnet_hex() {
        let magnet = "magnet:?xt=urn:btih:aabbccddeeff00112233445566778899aabbccdd&dn=test+file";
        let info = MagnetInfo::parse(magnet).unwrap();
        assert_eq!(info.info_hash[0], 0xAA);
        assert_eq!(info.info_hash[1], 0xBB);
        assert_eq!(info.display_name.as_deref(), Some("test file"));
    }

    #[test]
    fn parse_missing_xt_returns_error() {
        let err = MagnetInfo::parse("magnet:?dn=test").unwrap_err();
        assert!(matches!(err, PipelineError::InvalidMagnet(_)));
    }

    #[test]
    fn parse_non_magnet_uri_fails() {
        assert!(MagnetInfo::parse("https://example.com").is_err());
    }
}
