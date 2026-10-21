//! The byte layout of `root.sealed`.
//!
//! ```text
//! header (64 bytes, authenticated together with every record)
//!   magic "MSKR" 4 | version 1 | flags 1 | header_len (u16 LE) 2 | install_id 16
//!   | key_id 16 | created_epoch (u64 LE) 8 | root_check 16
//! records (one or more)
//!   type 1 | provider 1 | kdf_id 1 | params_len (u16 LE) 2 | kdf_params
//!   | wrapped_len (u32 LE) 4 | wrapped
//! ```
//!
//! A file with a higher version than this build knows is refused with
//! [`FormatError::FutureVersion`]; it is never read as if it were version 1.
//! Parsing is bounded and never panics on arbitrary input.

use std::fmt;

pub const MAGIC: &[u8; 4] = b"MSKR";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 64;

/// Flag: the owner chose to have no recovery wrap.
pub const FLAG_NO_RECOVERY: u8 = 1;
/// Flag: opening the key requires the user to be present.
pub const FLAG_PRESENCE: u8 = 2;

/// The wrap that this device opens.
pub const RECORD_DEVICE: u8 = 1;
/// The wrap made from a recovery code. A reserved slot: this build never
/// writes one and never needs one to open the key.
pub const RECORD_RECOVERY: u8 = 2;

/// Key derivation of a wrap: none, HKDF-SHA256, or Argon2id.
pub const KDF_NONE: u8 = 0;
pub const KDF_HKDF_SHA256: u8 = 1;
pub const KDF_ARGON2ID: u8 = 2;

const MAX_FILE_LEN: usize = 16 * 1024;
const MAX_PARAMS_LEN: usize = 256;
const MAX_WRAPPED_LEN: usize = 4096;
const MAX_RECORDS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    Truncated,
    BadMagic,
    /// Written by a newer program than this one.
    FutureVersion(u8),
    Corrupt(&'static str),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::Truncated => f.write_str("the file is cut short"),
            FormatError::BadMagic => f.write_str("the file is not a sealed key file"),
            FormatError::FutureVersion(v) => write!(
                f,
                "format version {v} is newer than this program understands (up to {VERSION})"
            ),
            FormatError::Corrupt(why) => write!(f, "the file is damaged ({why})"),
        }
    }
}

/// The 64-byte header. Holds no secret: `root_check` is a keyed hash that lets a
/// reader confirm it opened the right key without exposing it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub flags: u8,
    pub install_id: [u8; 16],
    pub key_id: [u8; 16],
    pub created_epoch: u64,
    pub root_check: [u8; 16],
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("flags", &self.flags)
            .field("created_epoch", &self.created_epoch)
            .finish_non_exhaustive()
    }
}

/// `root_check` of a key.
pub fn root_check(root: &[u8; 32]) -> [u8; 16] {
    let digest = blake3::keyed_hash(root, b"miasma/root-check/v1");
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest.as_bytes()[..16]);
    out
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..4].copy_from_slice(MAGIC);
        out[4] = VERSION;
        out[5] = self.flags;
        out[6..8].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
        out[8..24].copy_from_slice(&self.install_id);
        out[24..40].copy_from_slice(&self.key_id);
        out[40..48].copy_from_slice(&self.created_epoch.to_le_bytes());
        out[48..64].copy_from_slice(&self.root_check);
        out
    }

    fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() < 5 {
            return Err(FormatError::Truncated);
        }
        if &bytes[..4] != MAGIC {
            return Err(FormatError::BadMagic);
        }
        match bytes[4] {
            VERSION => {}
            0 => return Err(FormatError::Corrupt("version 0")),
            v => return Err(FormatError::FutureVersion(v)),
        }
        if bytes.len() < HEADER_LEN {
            return Err(FormatError::Truncated);
        }
        if u16::from_le_bytes([bytes[6], bytes[7]]) as usize != HEADER_LEN {
            return Err(FormatError::Corrupt("header length"));
        }
        let mut install_id = [0u8; 16];
        install_id.copy_from_slice(&bytes[8..24]);
        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&bytes[24..40]);
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(&bytes[40..48]);
        let mut check = [0u8; 16];
        check.copy_from_slice(&bytes[48..64]);
        Ok(Self {
            flags: bytes[5],
            install_id,
            key_id,
            created_epoch: u64::from_le_bytes(epoch),
            root_check: check,
        })
    }
}

/// One wrap of the root key.
#[derive(Clone, PartialEq, Eq)]
pub struct Record {
    pub rtype: u8,
    pub provider: u8,
    pub kdf_id: u8,
    pub kdf_params: Vec<u8>,
    pub wrapped: Vec<u8>,
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("rtype", &self.rtype)
            .field("provider", &self.provider)
            .field("kdf_id", &self.kdf_id)
            .field("wrapped_len", &self.wrapped.len())
            .finish()
    }
}

impl Record {
    /// The part of the record before `wrapped_len`, which is authenticated.
    pub fn head(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + self.kdf_params.len());
        out.push(self.rtype);
        out.push(self.provider);
        out.push(self.kdf_id);
        out.extend_from_slice(&(self.kdf_params.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.kdf_params);
        out
    }

    /// What a wrap authenticates: the whole header and this record's head.
    pub fn aad(&self, header: &Header) -> Vec<u8> {
        let mut aad = header.encode().to_vec();
        aad.extend_from_slice(&self.head());
        aad
    }
}

/// A parsed `root.sealed`.
#[derive(Clone, PartialEq, Eq)]
pub struct Blob {
    pub header: Header,
    pub records: Vec<Record>,
}

impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Blob")
            .field("header", &self.header)
            .field("records", &self.records)
            .finish()
    }
}

impl Blob {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.header.encode().to_vec();
        for r in &self.records {
            out.extend_from_slice(&r.head());
            out.extend_from_slice(&(r.wrapped.len() as u32).to_le_bytes());
            out.extend_from_slice(&r.wrapped);
        }
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > MAX_FILE_LEN {
            return Err(FormatError::Corrupt("too long"));
        }
        let header = Header::parse(bytes)?;
        let mut pos = HEADER_LEN;
        let mut records: Vec<Record> = Vec::new();
        while pos < bytes.len() {
            if records.len() >= MAX_RECORDS {
                return Err(FormatError::Corrupt("too many records"));
            }
            let fixed = bytes.get(pos..pos + 5).ok_or(FormatError::Truncated)?;
            let (rtype, provider, kdf_id) = (fixed[0], fixed[1], fixed[2]);
            let params_len = u16::from_le_bytes([fixed[3], fixed[4]]) as usize;
            if params_len > MAX_PARAMS_LEN {
                return Err(FormatError::Corrupt("parameters too long"));
            }
            pos += 5;
            let kdf_params = bytes
                .get(pos..pos + params_len)
                .ok_or(FormatError::Truncated)?
                .to_vec();
            pos += params_len;
            let len_bytes = bytes.get(pos..pos + 4).ok_or(FormatError::Truncated)?;
            let wrapped_len =
                u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]])
                    as usize;
            if wrapped_len > MAX_WRAPPED_LEN {
                return Err(FormatError::Corrupt("wrap too long"));
            }
            pos += 4;
            let wrapped = bytes
                .get(pos..pos + wrapped_len)
                .ok_or(FormatError::Truncated)?
                .to_vec();
            pos += wrapped_len;
            if rtype != RECORD_DEVICE && rtype != RECORD_RECOVERY {
                return Err(FormatError::Corrupt("unknown record type"));
            }
            if records.iter().any(|r| r.rtype == rtype) {
                return Err(FormatError::Corrupt("repeated record type"));
            }
            records.push(Record {
                rtype,
                provider,
                kdf_id,
                kdf_params,
                wrapped,
            });
        }
        if !records.iter().any(|r| r.rtype == RECORD_DEVICE) {
            return Err(FormatError::Corrupt("no device record"));
        }
        Ok(Self { header, records })
    }

    pub fn device_record(&self) -> &Record {
        // `parse` guarantees one; blobs built in memory always have one.
        self.records
            .iter()
            .find(|r| r.rtype == RECORD_DEVICE)
            .expect("a blob always holds a device record")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rnd<const N: usize>() -> [u8; N] {
        let mut b = [0u8; N];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
        b
    }

    pub(crate) fn sample() -> Blob {
        Blob {
            header: Header {
                flags: 0,
                install_id: rnd(),
                key_id: rnd(),
                created_epoch: 1_700_000_000,
                root_check: rnd(),
            },
            records: vec![Record {
                rtype: RECORD_DEVICE,
                provider: 0,
                kdf_id: KDF_HKDF_SHA256,
                kdf_params: vec![],
                wrapped: rnd::<72>().to_vec(),
            }],
        }
    }

    #[test]
    fn the_header_is_exactly_64_bytes_and_round_trips() {
        let b = sample();
        assert_eq!(b.header.encode().len(), 64);
        let bytes = b.encode();
        assert_eq!(Blob::parse(&bytes).unwrap(), b);
    }

    #[test]
    fn a_reserved_recovery_record_is_carried_along() {
        let mut b = sample();
        b.records.push(Record {
            rtype: RECORD_RECOVERY,
            provider: 8,
            kdf_id: KDF_HKDF_SHA256,
            kdf_params: vec![1, 2, 3],
            wrapped: rnd::<72>().to_vec(),
        });
        assert_eq!(Blob::parse(&b.encode()).unwrap(), b);
    }

    #[test]
    fn every_cut_of_a_valid_file_is_refused_without_a_panic() {
        let bytes = sample().encode();
        for cut in 0..bytes.len() {
            assert!(Blob::parse(&bytes[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn a_newer_version_is_named_not_misread() {
        let mut bytes = sample().encode();
        bytes[4] = VERSION + 1;
        assert_eq!(
            Blob::parse(&bytes),
            Err(FormatError::FutureVersion(VERSION + 1))
        );
        bytes[4] = 0;
        assert!(matches!(Blob::parse(&bytes), Err(FormatError::Corrupt(_))));
        // Even a file that stops after the version byte names the version.
        let mut short = b"MSKR".to_vec();
        short.push(9);
        assert_eq!(Blob::parse(&short), Err(FormatError::FutureVersion(9)));
    }

    #[test]
    fn malformed_files_are_refused() {
        let good = sample().encode();
        let mut b = good.clone();
        b[0] ^= 1;
        assert_eq!(Blob::parse(&b), Err(FormatError::BadMagic));
        let mut b = good.clone();
        b[6] = 65;
        assert!(matches!(Blob::parse(&b), Err(FormatError::Corrupt(_))));
        // Header only: no record.
        assert!(Blob::parse(&good[..HEADER_LEN]).is_err());
        // Unknown record type.
        let mut b = good.clone();
        b[HEADER_LEN] = 9;
        assert!(matches!(Blob::parse(&b), Err(FormatError::Corrupt(_))));
        // Only a recovery record.
        let mut b = good.clone();
        b[HEADER_LEN] = RECORD_RECOVERY;
        assert!(matches!(Blob::parse(&b), Err(FormatError::Corrupt(_))));
        // Trailing garbage reads as a truncated record.
        let mut b = good.clone();
        b.extend_from_slice(&[1, 2, 3]);
        assert!(Blob::parse(&b).is_err());
        // A repeated record type.
        let mut twice = sample();
        twice.records.push(twice.records[0].clone());
        assert!(matches!(
            Blob::parse(&twice.encode()),
            Err(FormatError::Corrupt(_))
        ));
        // Oversized lengths.
        let mut b = good.clone();
        b[HEADER_LEN + 3] = 0xff;
        b[HEADER_LEN + 4] = 0xff;
        assert!(Blob::parse(&b).is_err());
    }

    #[test]
    fn debug_output_has_no_key_material_fields() {
        let b = sample();
        let shown = format!("{b:?}");
        assert!(shown.contains("wrapped_len"));
        assert!(!shown.contains("install_id") && !shown.contains("root_check"));
    }
}
