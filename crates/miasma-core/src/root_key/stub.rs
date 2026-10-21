//! The 64-byte marker that stands in for `master.key` when the key is kept
//! somewhere else.
//!
//! Every released reader of `master.key` accepts exactly 32 bytes and refuses
//! anything else without creating a key. A file of any other length therefore
//! stops an older program with a plain length error instead of letting it start
//! over with a new key. The marker is 64 bytes, never 32, and holds no secret.
//!
//! This build only recognises the marker. It never writes one outside tests.

/// Length of the marker file. Must never equal the 32 bytes of a plain key.
pub const STUB_LEN: usize = 64;

const MAGIC: &[u8; 8] = b"MSKSTUB1";
const VERSION: u8 = 1;
/// Bytes covered by the check value: magic .. created_epoch.
const CHECKED_LEN: usize = 52;

/// What the marker says. No field is secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stub {
    pub provider: u8,
    pub flags: u16,
    pub install_id: [u8; 16],
    pub key_id: [u8; 16],
    pub created_epoch: u64,
}

/// Why a 64-byte file is not a valid marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubError {
    WrongLength,
    BadMagic,
    UnsupportedVersion(u8),
    BadCheck,
    BadPadding,
}

fn check_value(head: &[u8]) -> [u8; 8] {
    let digest = blake3::hash(head);
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest.as_bytes()[..8]);
    out
}

impl Stub {
    /// Serialise to exactly [`STUB_LEN`] bytes.
    pub fn encode(&self) -> [u8; STUB_LEN] {
        let mut out = [0u8; STUB_LEN];
        out[..8].copy_from_slice(MAGIC);
        out[8] = VERSION;
        out[9] = self.provider;
        out[10..12].copy_from_slice(&self.flags.to_le_bytes());
        out[12..28].copy_from_slice(&self.install_id);
        out[28..44].copy_from_slice(&self.key_id);
        out[44..52].copy_from_slice(&self.created_epoch.to_le_bytes());
        let check = check_value(&out[..CHECKED_LEN]);
        out[52..60].copy_from_slice(&check);
        out
    }

    /// Parse and verify a marker.
    pub fn parse(bytes: &[u8]) -> Result<Self, StubError> {
        if bytes.len() != STUB_LEN {
            return Err(StubError::WrongLength);
        }
        if &bytes[..8] != MAGIC {
            return Err(StubError::BadMagic);
        }
        if bytes[8] != VERSION {
            return Err(StubError::UnsupportedVersion(bytes[8]));
        }
        if bytes[52..60] != check_value(&bytes[..CHECKED_LEN]) {
            return Err(StubError::BadCheck);
        }
        if bytes[60..].iter().any(|b| *b != 0) {
            return Err(StubError::BadPadding);
        }
        let mut install_id = [0u8; 16];
        install_id.copy_from_slice(&bytes[12..28]);
        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&bytes[28..44]);
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(&bytes[44..52]);
        Ok(Self {
            provider: bytes[9],
            flags: u16::from_le_bytes([bytes[10], bytes[11]]),
            install_id,
            key_id,
            created_epoch: u64::from_le_bytes(epoch),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Stub {
        let mut install_id = [0u8; 16];
        let mut key_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut install_id);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key_id);
        Stub {
            provider: 1,
            flags: 0,
            install_id,
            key_id,
            created_epoch: 1_700_000_000,
        }
    }

    #[test]
    fn the_marker_is_never_32_bytes_and_round_trips() {
        assert_ne!(STUB_LEN, 32);
        let s = sample();
        let bytes = s.encode();
        assert_eq!(bytes.len(), 64);
        assert_eq!(Stub::parse(&bytes), Ok(s));
    }

    #[test]
    fn damage_is_detected() {
        let bytes = sample().encode();
        assert_eq!(Stub::parse(&bytes[..63]), Err(StubError::WrongLength));
        let mut b = bytes;
        b[0] ^= 1;
        assert_eq!(Stub::parse(&b), Err(StubError::BadMagic));
        let mut b = bytes;
        b[8] = 9;
        assert_eq!(Stub::parse(&b), Err(StubError::UnsupportedVersion(9)));
        let mut b = bytes;
        b[20] ^= 1;
        assert_eq!(Stub::parse(&b), Err(StubError::BadCheck));
        let mut b = bytes;
        b[63] = 1;
        assert_eq!(Stub::parse(&b), Err(StubError::BadPadding));
    }
}
