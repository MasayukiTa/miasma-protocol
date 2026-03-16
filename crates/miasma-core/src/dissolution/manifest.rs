/// DissolutionManifest — tracks all segments of a multi-segment dissolution.
///
/// A manifest enables:
/// - Streaming dissolution (process one 64 MB segment at a time)
/// - Parallel retrieval (fetch segments independently)
/// - Partial re-dissolution (re-process only failed segments)
use serde::{Deserialize, Serialize};

use crate::{crypto::hash::ContentId, pipeline::DissolutionParams, MiasmaError};

/// Default segment size: 64 MiB.
pub const DEFAULT_SEGMENT_SIZE: usize = 64 * 1024 * 1024;

/// Per-segment metadata stored inside `DissolutionManifest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentMeta {
    /// Segment index (0-based).
    pub index: u32,
    /// Byte offset of this segment in the original plaintext file.
    pub offset_bytes: u64,
    /// Plaintext length of this segment in bytes.
    pub plaintext_len: u32,
    /// Total share count for this segment (= total_shards).
    pub share_count: u16,
}

/// Manifest describing a full multi-segment dissolution.
///
/// Stored alongside shares so that retrieval knows how many segments exist
/// and in what order to reassemble them. The manifest itself is small
/// (O(segments) ≈ O(file_size / 64 MB)) and should be stored with k shares.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DissolutionManifest {
    /// Protocol version (currently 1).
    pub version: u8,
    /// Content identifier of the full file.
    pub mid: ContentId,
    /// Dissolution parameters (k, n) used for every segment.
    pub params: DissolutionParams,
    /// Total plaintext file size in bytes.
    pub total_bytes: u64,
    /// Segment size used during dissolution (bytes).
    pub segment_size: u32,
    /// Per-segment metadata, ordered by `index`.
    pub segments: Vec<SegmentMeta>,
    /// Unix timestamp (seconds) when the manifest was created.
    pub created_at: u64,
}

impl DissolutionManifest {
    /// Serialize to bytes (bincode).
    pub fn to_bytes(&self) -> Result<Vec<u8>, MiasmaError> {
        bincode::serialize(self).map_err(|e| MiasmaError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes (bincode).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MiasmaError> {
        bincode::deserialize(bytes).map_err(|e| MiasmaError::Serialization(e.to_string()))
    }

    /// Number of segments in this dissolution.
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Total share count across all segments.
    pub fn total_share_count(&self) -> usize {
        self.segments.iter().map(|s| s.share_count as usize).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::DissolutionParams;

    fn dummy_manifest() -> DissolutionManifest {
        let mid = ContentId::compute(b"test content", b"k=10,n=20,v=1");
        DissolutionManifest {
            version: 1,
            mid,
            params: DissolutionParams::default(),
            total_bytes: 1024,
            segment_size: DEFAULT_SEGMENT_SIZE as u32,
            segments: vec![SegmentMeta {
                index: 0,
                offset_bytes: 0,
                plaintext_len: 1024,
                share_count: 20,
            }],
            created_at: 0,
        }
    }

    #[test]
    fn manifest_serialization_roundtrip() {
        let m = dummy_manifest();
        let bytes = m.to_bytes().unwrap();
        let m2 = DissolutionManifest::from_bytes(&bytes).unwrap();
        assert_eq!(m.total_bytes, m2.total_bytes);
        assert_eq!(m.segments.len(), m2.segments.len());
        assert_eq!(m.mid, m2.mid);
    }

    #[test]
    fn total_share_count() {
        let mut m = dummy_manifest();
        m.segments.push(SegmentMeta {
            index: 1,
            offset_bytes: 1024,
            plaintext_len: 512,
            share_count: 20,
        });
        assert_eq!(m.total_share_count(), 40);
    }
}
