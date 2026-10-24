//! The canonical associated-data layout of a Suite2 segment.
//!
//! Fixed length, 49 bytes, little-endian integers (to match the piece
//! commitment in `share.rs`). No field is variable-length, so there is no
//! length prefix and no separator. Changing any byte makes decryption fail:
//! the receiver rebuilds the AAD from values it holds independently of the
//! ciphertext (the manifest, or the selected shares) and the AES-GCM tag only
//! verifies if they match what the sender bound.
//!
//! ```text
//! offset len  field
//! 0      4    magic          = "MSA2"
//! 4      2    suite: u16le   = ObjectSuite id (2 = Suite2)
//! 6      1    context: u8    1 = transfer segment, 2 = whole-file, 3 = directed
//! 7      32   mid            full 32-byte MID digest
//! 39     4    segment_index: u32le   (whole-file / directed: 0)
//! 43     1    data_shards: u8   (k)
//! 44     1    total_shards: u8  (n)
//! 45     4    plaintext_len: u32le
//! = 49 bytes
//! ```

use crate::crypto::hash::ContentId;

use super::{FormatError, ObjectSuite};

/// Length of the canonical segment AAD, in bytes.
pub const AAD_LEN: usize = 49;

/// The four magic bytes at the start of the AAD ("Miasma Segment AAD, layout 2").
pub const AAD_MAGIC: [u8; 4] = *b"MSA2";

/// Whether and how the segment AEAD binds associated data. Carried by
/// [`super::SuiteSpec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AadLayout {
    /// No associated data (Suite1): the AEAD is called with an empty AAD.
    None,
    /// The 49-byte layout of this module (Suite2).
    Msa2,
}

/// What the segment is for. Separates the transfer segment, the whole-file
/// dissolve and the directed body so the same key material cannot be replayed
/// across uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AadContext {
    /// A segment of a transfer (manifest present).
    TransferSegment = 1,
    /// A whole-file dissolve (no manifest).
    WholeFile = 2,
    /// The body of a directed message.
    Directed = 3,
}

impl AadContext {
    /// The one-byte wire value.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Recover a context from its wire byte.
    pub fn from_u8(v: u8) -> Result<Self, FormatError> {
        match v {
            1 => Ok(Self::TransferSegment),
            2 => Ok(Self::WholeFile),
            3 => Ok(Self::Directed),
            _ => Err(FormatError::Unrepresentable("context byte out of range")),
        }
    }
}

/// The fields bound into a Suite2 segment's associated data. Build it from the
/// values the receiver can obtain independently of the ciphertext, then call
/// [`SegmentAad::encode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentAad {
    /// The object suite (Suite2 for the AAD to be present at all).
    pub suite: ObjectSuite,
    /// What the segment is for.
    pub context: AadContext,
    /// The full 32-byte MID digest (not the 8-byte prefix).
    pub mid: [u8; 32],
    /// The segment index within the file (0 for whole-file and directed).
    pub segment_index: u32,
    /// Data shards (k).
    pub data_shards: u8,
    /// Total shards (n).
    pub total_shards: u8,
    /// Plaintext length of this segment, in bytes.
    pub plaintext_len: u32,
}

impl SegmentAad {
    /// Build the AAD for a transfer or whole-file segment, converting the
    /// `usize` shard counts and plaintext length to their fixed-width forms.
    ///
    /// Returns [`FormatError::Unrepresentable`] if `data_shards` or
    /// `total_shards` exceed 255, or if `plaintext_len` exceeds `u32::MAX`.
    pub fn new(
        suite: ObjectSuite,
        context: AadContext,
        mid: &ContentId,
        segment_index: u32,
        data_shards: usize,
        total_shards: usize,
        plaintext_len: usize,
    ) -> Result<Self, FormatError> {
        let data_shards = u8::try_from(data_shards)
            .map_err(|_| FormatError::Unrepresentable("data_shards above 255"))?;
        let total_shards = u8::try_from(total_shards)
            .map_err(|_| FormatError::Unrepresentable("total_shards above 255"))?;
        let plaintext_len = u32::try_from(plaintext_len)
            .map_err(|_| FormatError::Unrepresentable("plaintext_len above u32::MAX"))?;
        Ok(Self {
            suite,
            context,
            mid: *mid.as_bytes(),
            segment_index,
            data_shards,
            total_shards,
            plaintext_len,
        })
    }

    /// Serialize to the fixed 49-byte canonical form.
    pub fn encode(&self) -> [u8; AAD_LEN] {
        let mut out = [0u8; AAD_LEN];
        out[0..4].copy_from_slice(&AAD_MAGIC);
        out[4..6].copy_from_slice(&self.suite.id().to_le_bytes());
        out[6] = self.context.as_u8();
        out[7..39].copy_from_slice(&self.mid);
        out[39..43].copy_from_slice(&self.segment_index.to_le_bytes());
        out[43] = self.data_shards;
        out[44] = self.total_shards;
        out[45..49].copy_from_slice(&self.plaintext_len.to_le_bytes());
        out
    }

    /// Parse a 49-byte AAD back into its fields. Rejects a wrong magic, an
    /// unknown suite id and an out-of-range context. Used by tests and by any
    /// reader that needs to inspect a bound AAD; the AEAD itself only needs the
    /// bytes from [`encode`].
    pub fn decode(bytes: &[u8; AAD_LEN]) -> Result<Self, FormatError> {
        if bytes[0..4] != AAD_MAGIC {
            return Err(FormatError::Unrepresentable("wrong AAD magic"));
        }
        let suite = ObjectSuite::from_id(u16::from_le_bytes([bytes[4], bytes[5]]))?;
        let context = AadContext::from_u8(bytes[6])?;
        let mut mid = [0u8; 32];
        mid.copy_from_slice(&bytes[7..39]);
        let segment_index = u32::from_le_bytes([bytes[39], bytes[40], bytes[41], bytes[42]]);
        let data_shards = bytes[43];
        let total_shards = bytes[44];
        let plaintext_len = u32::from_le_bytes([bytes[45], bytes[46], bytes[47], bytes[48]]);
        Ok(Self {
            suite,
            context,
            mid,
            segment_index,
            data_shards,
            total_shards,
            plaintext_len,
        })
    }
}

/// Encode the canonical 49-byte Suite2 segment AAD directly from its fields.
///
/// This is the free-function form used where the caller already holds each
/// field as its fixed-width type (for example the key-derivation and sealing
/// path, and the known-answer tests). `context` is the raw wire byte of
/// [`AadContext`] (1 = transfer, 2 = whole-file, 3 = directed); `suite` is the
/// [`ObjectSuite`] whose [`ObjectSuite::id`] is written into the layout.
///
/// It mirrors [`SegmentAad::encode`] byte for byte; the struct form is kept for
/// callers that build the AAD from `usize` counts and want the range checks of
/// [`SegmentAad::new`].
pub fn encode_aad(
    suite: ObjectSuite,
    context: u8,
    mid: &[u8; 32],
    segment_index: u32,
    data_shards: u8,
    total_shards: u8,
    plaintext_len: u32,
) -> [u8; AAD_LEN] {
    let mut out = [0u8; AAD_LEN];
    out[0..4].copy_from_slice(&AAD_MAGIC);
    out[4..6].copy_from_slice(&suite.id().to_le_bytes());
    out[6] = context;
    out[7..39].copy_from_slice(mid);
    out[39..43].copy_from_slice(&segment_index.to_le_bytes());
    out[43] = data_shards;
    out[44] = total_shards;
    out[45..49].copy_from_slice(&plaintext_len.to_le_bytes());
    out
}
