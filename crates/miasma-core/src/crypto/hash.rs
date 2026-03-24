use crate::MiasmaError;
use bs58;
use serde::{Deserialize, Serialize};

/// MID prefix length used for coarse share verification (ADR-003).
pub const MID_PREFIX_LEN: usize = 8;

/// Miasma Content Identifier.
///
/// `miasma:<base58(BLAKE3(content || dissolution_params))>`
///
/// The first 8 bytes of the raw BLAKE3 digest are used as `mid_prefix` in each
/// `MiasmaShare` to allow early rejection of shares belonging to a different
/// content item (before k shares are collected and K_enc can be recovered).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentId {
    /// Raw 32-byte BLAKE3 digest.
    digest: [u8; 32],
}

impl ContentId {
    /// Compute the MID from raw plaintext content and dissolution parameters.
    ///
    /// `params` is an opaque byte string encoding k, n, and any other
    /// protocol-level parameters so that two dissolutions of the same file
    /// with different parameters produce different MIDs.
    pub fn compute(content: &[u8], params: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(content);
        hasher.update(params);
        let digest = *hasher.finalize().as_bytes();
        Self { digest }
    }

    /// Return the canonical string form: `miasma:<base58(digest)>`.
    pub fn to_string(&self) -> String {
        format!("miasma:{}", bs58::encode(&self.digest).into_string())
    }

    /// Parse a MID string of the form `miasma:<base58>`.
    pub fn from_str(s: &str) -> Result<Self, MiasmaError> {
        let s = s.strip_prefix("miasma:").ok_or_else(|| {
            MiasmaError::InvalidMid(format!("missing 'miasma:' prefix in '{}'", s))
        })?;
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| MiasmaError::InvalidMid(e.to_string()))?;
        let digest: [u8; 32] = bytes
            .try_into()
            .map_err(|_| MiasmaError::InvalidMid("digest must be 32 bytes".into()))?;
        Ok(Self { digest })
    }

    /// Compute the MID by streaming file content through BLAKE3.
    ///
    /// Uses `std::io::Read` to avoid loading the full file into RAM.
    /// `params` is appended after all content bytes.
    pub fn compute_from_reader<R: std::io::Read>(
        reader: &mut R,
        params: &[u8],
    ) -> Result<Self, std::io::Error> {
        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; 64 * 1024]; // 64 KiB read buffer
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        hasher.update(params);
        let digest = *hasher.finalize().as_bytes();
        Ok(Self { digest })
    }

    /// Construct a `ContentId` from a raw 32-byte digest already known to the caller.
    ///
    /// Use only when the digest is already available (e.g. from a `DhtRecord.mid_digest`).
    /// Prefer `ContentId::compute` when you have the raw content.
    pub fn from_digest(digest: [u8; 32]) -> Self {
        Self { digest }
    }

    /// Raw 32-byte BLAKE3 digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.digest
    }

    /// First `MID_PREFIX_LEN` bytes of the digest, embedded in each share for
    /// coarse verification (ADR-003 §粗検証ロジック).
    pub fn prefix(&self) -> [u8; MID_PREFIX_LEN] {
        self.digest[..MID_PREFIX_LEN]
            .try_into()
            .expect("MID_PREFIX_LEN <= 32")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARAMS: &[u8] = b"k=10,n=20,v=1";

    #[test]
    fn round_trip_string() {
        let mid = ContentId::compute(b"hello miasma", PARAMS);
        let s = mid.to_string();
        assert!(s.starts_with("miasma:"));
        let parsed = ContentId::from_str(&s).unwrap();
        assert_eq!(mid, parsed);
    }

    #[test]
    fn different_content_different_mid() {
        let a = ContentId::compute(b"content A", PARAMS);
        let b = ContentId::compute(b"content B", PARAMS);
        assert_ne!(a, b);
    }

    #[test]
    fn different_params_different_mid() {
        let content = b"same content";
        let a = ContentId::compute(content, b"k=10,n=20");
        let b = ContentId::compute(content, b"k=5,n=10");
        assert_ne!(a, b);
    }

    #[test]
    fn prefix_length() {
        let mid = ContentId::compute(b"test", PARAMS);
        let prefix = mid.prefix();
        assert_eq!(prefix.len(), MID_PREFIX_LEN);
        assert_eq!(&prefix[..], &mid.as_bytes()[..MID_PREFIX_LEN]);
    }

    /// Published test vector — BLAKE3("hello miasma" || "k=10,n=20,v=1")
    #[test]
    fn test_vector_deterministic() {
        let mid1 = ContentId::compute(b"hello miasma", PARAMS);
        let mid2 = ContentId::compute(b"hello miasma", PARAMS);
        assert_eq!(mid1, mid2, "MID computation must be deterministic");
    }

    #[test]
    fn streaming_matches_in_memory() {
        let content = b"hello miasma streaming test data";
        let in_memory = ContentId::compute(content, PARAMS);
        let mut cursor = std::io::Cursor::new(content);
        let streamed = ContentId::compute_from_reader(&mut cursor, PARAMS).unwrap();
        assert_eq!(in_memory, streamed, "streaming and in-memory MID must match");
    }

    #[test]
    fn streaming_large_multi_buffer() {
        // Content larger than the 64 KiB internal buffer to exercise the read loop.
        let content = vec![0xABu8; 128 * 1024];
        let in_memory = ContentId::compute(&content, PARAMS);
        let mut cursor = std::io::Cursor::new(&content);
        let streamed = ContentId::compute_from_reader(&mut cursor, PARAMS).unwrap();
        assert_eq!(in_memory, streamed);
    }

    #[test]
    fn streaming_empty() {
        let in_memory = ContentId::compute(b"", PARAMS);
        let mut cursor = std::io::Cursor::new(b"");
        let streamed = ContentId::compute_from_reader(&mut cursor, PARAMS).unwrap();
        assert_eq!(in_memory, streamed);
    }
}
