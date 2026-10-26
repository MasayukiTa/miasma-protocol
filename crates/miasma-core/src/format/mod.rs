//! Object format descriptors: the one place that names the wire versions of a
//! stored or transferred object and ties them to the AEAD, the AAD layout, the
//! key-derivation labels and the key schedule used to seal a segment.
//!
//! A single [`ObjectSuite`] fixes the share version, the manifest version, the
//! directed-envelope version, the two key labels and whether the segment AEAD
//! carries associated data. Nothing here changes the bytes of an existing
//! object: [`ObjectSuite::Suite1`] describes exactly what shipped builds write
//! (AES-256-GCM with no AAD, `K_aes = K_enc` or the v1 HKDF label), and
//! [`ObjectSuite::Suite2`] describes the new form (the 49-byte AAD of
//! [`aad`], `K_aes = HKDF("miasma-seg-key-v2" || AAD)`).
//!
//! The writer is unchanged: the new parts here are not yet called from any
//! publish or save path.

pub mod aad;
pub mod seal;

pub use aad::{encode_aad, AadContext, AadLayout, SegmentAad, AAD_LEN};
pub use seal::{open_segment, seal_segment};

/// A format error that must surface as "update Miasma" rather than silently
/// falling back to an older suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    /// A version number this build does not recognise. Carries the value seen
    /// so the caller can tell the user which object is too new.
    Newer(u16),
    /// A field that cannot be encoded into the fixed-width AAD (for example a
    /// shard count above 255 or a plaintext length above `u32::MAX`).
    Unrepresentable(&'static str),
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormatError::Newer(v) => {
                write!(
                    f,
                    "object format {v} is newer than this build supports; update Miasma"
                )
            }
            FormatError::Unrepresentable(what) => {
                write!(f, "value does not fit the segment AAD: {what}")
            }
        }
    }
}

impl std::error::Error for FormatError {}

/// One object format. The `#[repr(u16)]` discriminant is the `suite` value
/// written into the AAD and (for Suite2) the manifest.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ObjectSuite {
    /// Read-only, forever. AES-256-GCM without AAD, `K_aes = K_enc` (no
    /// password) or `HKDF("miasma-seg-key-v1" || mid || seg_le)` (password),
    /// sealed name `"miasma-name-key-v1"` without AAD.
    Suite1 = 1,
    /// AES-256-GCM with the 49-byte AAD (see [`aad`]),
    /// `K_aes = HKDF(salt = pw_key or empty, ikm = K_enc,
    /// info = "miasma-seg-key-v2" || AAD)`, sealed name with AAD.
    Suite2 = 2,
}

/// The fixed properties of one [`ObjectSuite`]. Every field is a compile-time
/// constant; there is one `SuiteSpec` per suite and it is never built at run
/// time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuiteSpec {
    /// Value of `MiasmaShare.version` for this suite.
    pub share_version: u8,
    /// Value of the transfer manifest version / trailer version.
    pub manifest_version: u8,
    /// Value of `DirectedEnvelope.version`.
    pub directed_envelope_version: u8,
    /// HKDF `info` label prefix for the segment key.
    pub segment_key_label: &'static [u8],
    /// HKDF `info` label for the sealed name.
    pub name_key_label: &'static [u8],
    /// Whether and how the segment AEAD binds associated data.
    pub aad: AadLayout,
}

const SPEC_SUITE1: SuiteSpec = SuiteSpec {
    share_version: 1,
    manifest_version: 3,
    directed_envelope_version: 1,
    segment_key_label: b"miasma-seg-key-v1",
    name_key_label: b"miasma-name-key-v1",
    aad: AadLayout::None,
};

const SPEC_SUITE2: SuiteSpec = SuiteSpec {
    share_version: 2,
    manifest_version: 4,
    directed_envelope_version: 2,
    segment_key_label: b"miasma-seg-key-v2",
    name_key_label: b"miasma-name-key-v2",
    aad: AadLayout::Msa2,
};

impl ObjectSuite {
    /// The suites this build reads, newest last. A reader tries each in turn;
    /// a version outside this set is `FormatError::Newer`.
    pub const CURRENT_READ: &'static [ObjectSuite] = &[Self::Suite1, Self::Suite2];

    /// The fixed properties of this suite.
    pub fn spec(self) -> &'static SuiteSpec {
        match self {
            Self::Suite1 => &SPEC_SUITE1,
            Self::Suite2 => &SPEC_SUITE2,
        }
    }

    /// The `suite` value as written into the AAD and the manifest.
    pub fn id(self) -> u16 {
        self as u16
    }

    /// Map a `MiasmaShare.version` to its suite.
    pub fn from_share_version(v: u8) -> Result<Self, FormatError> {
        match v {
            1 => Ok(Self::Suite1),
            2 => Ok(Self::Suite2),
            other => Err(FormatError::Newer(other as u16)),
        }
    }

    /// Map a transfer manifest / trailer version to its suite.
    pub fn from_manifest_version(v: u8) -> Result<Self, FormatError> {
        match v {
            3 => Ok(Self::Suite1),
            4 => Ok(Self::Suite2),
            other => Err(FormatError::Newer(other as u16)),
        }
    }

    /// Map a `DirectedEnvelope.version` to its suite.
    pub fn from_envelope_version(v: u8) -> Result<Self, FormatError> {
        match v {
            1 => Ok(Self::Suite1),
            2 => Ok(Self::Suite2),
            other => Err(FormatError::Newer(other as u16)),
        }
    }

    /// Recover a suite from its `#[repr(u16)]` id (the value in the AAD).
    pub fn from_id(id: u16) -> Result<Self, FormatError> {
        match id {
            1 => Ok(Self::Suite1),
            2 => Ok(Self::Suite2),
            other => Err(FormatError::Newer(other)),
        }
    }

    /// Whether this is the older object format. Suite1 is what shipped builds
    /// write today; a reader shows such an object as the legacy ("old format")
    /// form in its status. Suite2 is the newer form.
    pub fn is_legacy(self) -> bool {
        matches!(self, Self::Suite1)
    }

    /// A short, neutral label for the object format, for status display.
    /// Returns "legacy" for Suite1 and "current" for Suite2.
    pub fn status_label(self) -> &'static str {
        if self.is_legacy() {
            "legacy"
        } else {
            "current"
        }
    }
}
