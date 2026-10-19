//! Capability sets and negotiation.
//!
//! # Rules
//!
//! * Negotiation picks the highest level both sides support. Unknown versions,
//!   unknown suite bits and unknown feature bits are ignored, never an error.
//! * The classical baseline suite ([`SUITE_CLASSICAL`]) is implicit on both
//!   sides: every build implements it, and a peer that sends no capability
//!   message at all is treated as [`Capabilities::legacy`]. So negotiation
//!   always has at least one common suite.
//! * The only failure is the local policy: if the local side *requires* a
//!   suite or feature that the agreed set lacks, [`negotiate`] returns
//!   [`NegotiationError::RequirementUnmet`]. A peer's inability is never
//!   silently accepted when the local side demanded the feature.
//! * When the agreed level is below what the local side offered,
//!   [`Agreed::downgraded`] is true and [`Agreed::reasons`] says why, so the
//!   caller can show it. [`transcript_binding`] hashes both offers and the
//!   result so a handshake can authenticate them and detect tampering.
//!
//! # Wire encoding (all integers big-endian)
//!
//! ```text
//! version   u16
//! suites    u32   bitset
//! features  u32   bitset
//! ext_len   u16
//! ext       ext_len bytes   opaque, preserved and re-encoded unchanged
//! ```
//!
//! The first four fields keep their meaning in every future version. Bytes
//! after `ext` are ignored when the version is newer than ours and rejected
//! otherwise (canonical form).

use thiserror::Error;

/// Highest capability-structure version this build speaks.
pub const CAPABILITY_VERSION: u16 = 1;

/// Classical X25519-based handshake. Always implied.
pub const SUITE_CLASSICAL: u32 = 1 << 0;
/// Hybrid classical + post-quantum handshake (reserved id, not yet usable).
pub const SUITE_HYBRID_X25519_MLKEM768: u32 = 1 << 1;
/// Suite bits this build knows about.
pub const KNOWN_SUITES: u32 = SUITE_CLASSICAL | SUITE_HYBRID_X25519_MLKEM768;

/// Handshake messages may be split with `protocol::fragment`.
pub const FEATURE_FRAGMENTATION: u32 = 1 << 0;
/// Feature bits this build knows about.
pub const KNOWN_FEATURES: u32 = FEATURE_FRAGMENTATION;

/// Maximum length of the opaque extension block.
pub const MAX_EXT_LEN: usize = 256;

const FIXED_LEN: usize = 2 + 4 + 4 + 2;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CapabilityError {
    #[error("capability encoding truncated")]
    Truncated,
    #[error("extension block of {0} bytes exceeds the {MAX_EXT_LEN} byte cap")]
    ExtTooLong(usize),
    #[error("unexpected trailing bytes in a capability encoding")]
    TrailingBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NegotiationError {
    #[error("required suites {missing_suites:#x} / features {missing_features:#x} not available")]
    RequirementUnmet {
        missing_suites: u32,
        missing_features: u32,
    },
}

/// What one side supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    pub version: u16,
    pub suites: u32,
    pub features: u32,
    /// Opaque extension bytes from a newer peer, passed through unchanged.
    pub unknown: Vec<u8>,
}

impl Capabilities {
    /// Everything this build supports.
    pub fn current() -> Self {
        Self {
            version: CAPABILITY_VERSION,
            suites: KNOWN_SUITES,
            features: KNOWN_FEATURES,
            unknown: Vec::new(),
        }
    }

    /// A peer that predates capability negotiation: classical only.
    pub fn legacy() -> Self {
        Self {
            version: 0,
            suites: SUITE_CLASSICAL,
            features: 0,
            unknown: Vec::new(),
        }
    }

    pub fn with_unknown(mut self, ext: Vec<u8>) -> Result<Self, CapabilityError> {
        if ext.len() > MAX_EXT_LEN {
            return Err(CapabilityError::ExtTooLong(ext.len()));
        }
        self.unknown = ext;
        Ok(self)
    }

    /// Canonical encoding. Extension bytes beyond [`MAX_EXT_LEN`] are cut off
    /// (only reachable by building the struct by hand).
    pub fn encode(&self) -> Vec<u8> {
        let ext = &self.unknown[..self.unknown.len().min(MAX_EXT_LEN)];
        let mut out = Vec::with_capacity(FIXED_LEN + ext.len());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.suites.to_be_bytes());
        out.extend_from_slice(&self.features.to_be_bytes());
        out.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        out.extend_from_slice(ext);
        out
    }

    /// Decode. Never fails because of an unknown version or unknown bits.
    pub fn decode(buf: &[u8]) -> Result<Self, CapabilityError> {
        if buf.len() < FIXED_LEN {
            return Err(CapabilityError::Truncated);
        }
        let version = u16::from_be_bytes([buf[0], buf[1]]);
        let suites = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        let features = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
        let ext_len = u16::from_be_bytes([buf[10], buf[11]]) as usize;
        if ext_len > MAX_EXT_LEN {
            return Err(CapabilityError::ExtTooLong(ext_len));
        }
        let rest = &buf[FIXED_LEN..];
        if rest.len() < ext_len {
            return Err(CapabilityError::Truncated);
        }
        if rest.len() > ext_len && version <= CAPABILITY_VERSION {
            return Err(CapabilityError::TrailingBytes);
        }
        Ok(Self {
            version,
            suites,
            features,
            unknown: rest[..ext_len].to_vec(),
        })
    }
}

/// Local policy: what we demand. Empty means "accept whatever is common".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Requirements {
    pub suites: u32,
    pub features: u32,
}

/// Why the agreed level is below the local offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DowngradeReason {
    /// Peer speaks an older capability version.
    PeerOlderVersion { local: u16, remote: u16 },
    /// Suites we offered that the peer lacks.
    SuitesUnavailable { bits: u32 },
    /// Features we offered that the peer lacks.
    FeaturesUnavailable { bits: u32 },
}

/// Result of a negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agreed {
    pub version: u16,
    /// Suites both sides support (always includes the classical baseline).
    pub suites: u32,
    pub features: u32,
    pub downgraded: bool,
    pub reasons: Vec<DowngradeReason>,
}

impl Agreed {
    /// The strongest agreed suite: the highest known suite bit in common.
    pub fn best_suite(&self) -> u32 {
        let known = self.suites & KNOWN_SUITES;
        if known == 0 {
            SUITE_CLASSICAL
        } else {
            1 << (31 - known.leading_zeros())
        }
    }

    pub fn has_suite(&self, suite: u32) -> bool {
        self.suites & suite == suite
    }

    pub fn has_feature(&self, feature: u32) -> bool {
        self.features & feature == feature
    }

    /// Canonical encoding of the agreed result (excluding the human reasons).
    fn encode(&self) -> [u8; 10] {
        let mut out = [0u8; 10];
        out[0..2].copy_from_slice(&self.version.to_be_bytes());
        out[2..6].copy_from_slice(&self.suites.to_be_bytes());
        out[6..10].copy_from_slice(&self.features.to_be_bytes());
        out
    }
}

/// Pick the highest common level. Unknown versions and bits are ignored.
/// Fails only when `require` demands something that is not agreed.
pub fn negotiate(
    local: &Capabilities,
    remote: &Capabilities,
    require: &Requirements,
) -> Result<Agreed, NegotiationError> {
    let local_suites = local.suites | SUITE_CLASSICAL;
    let remote_suites = remote.suites | SUITE_CLASSICAL;
    let version = local.version.min(remote.version);
    let suites = local_suites & remote_suites;
    let features = local.features & remote.features;

    let missing_suites = require.suites & !suites;
    let missing_features = require.features & !features;
    if missing_suites != 0 || missing_features != 0 {
        return Err(NegotiationError::RequirementUnmet {
            missing_suites,
            missing_features,
        });
    }

    let mut reasons = Vec::new();
    if remote.version < local.version {
        reasons.push(DowngradeReason::PeerOlderVersion {
            local: local.version,
            remote: remote.version,
        });
    }
    let lost_suites = local_suites & !suites;
    if lost_suites != 0 {
        reasons.push(DowngradeReason::SuitesUnavailable { bits: lost_suites });
    }
    let lost_features = local.features & !features;
    if lost_features != 0 {
        reasons.push(DowngradeReason::FeaturesUnavailable {
            bits: lost_features,
        });
    }
    Ok(Agreed {
        version,
        suites,
        features,
        downgraded: !reasons.is_empty(),
        reasons,
    })
}

const BINDING_CONTEXT: &str = "miasma protocol capability transcript binding v1";

fn put_lp(h: &mut blake3::Hasher, bytes: &[u8]) {
    h.update(&(bytes.len() as u32).to_be_bytes());
    h.update(bytes);
}

/// Domain-separated hash of both offers and the agreed result, for a
/// handshake to include in its transcript. If an on-path party edits either
/// offer to force a lower level, the two sides compute different values and
/// the handshake authentication fails.
pub fn transcript_binding(
    initiator: &Capabilities,
    responder: &Capabilities,
    agreed: &Agreed,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(BINDING_CONTEXT);
    put_lp(&mut h, &initiator.encode());
    put_lp(&mut h, &responder.encode());
    put_lp(&mut h, &agreed.encode());
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(version: u16, suites: u32, features: u32) -> Capabilities {
        Capabilities {
            version,
            suites,
            features,
            unknown: Vec::new(),
        }
    }

    #[test]
    fn frozen_encoding() {
        let c = Capabilities {
            version: 1,
            suites: 0b11,
            features: 1,
            unknown: vec![0xAA, 0xBB],
        };
        assert_eq!(
            hex::encode(c.encode()),
            concat!("0001", "00000003", "00000001", "0002", "aabb")
        );
        assert_eq!(
            hex::encode(Capabilities::legacy().encode()),
            "000000000001000000000000"
        );
    }

    #[test]
    fn frozen_binding() {
        let a = Capabilities::current();
        let b = Capabilities::legacy();
        let agreed = negotiate(&a, &b, &Requirements::default()).unwrap();
        let d = transcript_binding(&a, &b, &agreed);
        // Changing any input must change the digest; the exact value is frozen.
        assert_eq!(hex::encode(d), FROZEN_BINDING);
    }

    // Guards the domain string and layout of the binding input.
    const FROZEN_BINDING: &str =
        "96ad53b290d8ade644d3a0d42472489e232285f9f150f85051f24aef711f7a33";

    #[test]
    fn round_trip() {
        let c = Capabilities::current().with_unknown(vec![1, 2, 3]).unwrap();
        assert_eq!(Capabilities::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn decode_rejects_truncation_and_long_ext() {
        let e = Capabilities::current().encode();
        for n in 0..e.len() {
            assert!(Capabilities::decode(&e[..n]).is_err(), "len {n}");
        }
        let mut bad = Capabilities::current().encode();
        bad[10..12].copy_from_slice(&((MAX_EXT_LEN as u16) + 1).to_be_bytes());
        assert!(matches!(
            Capabilities::decode(&bad),
            Err(CapabilityError::ExtTooLong(_))
        ));
        assert!(Capabilities::current()
            .with_unknown(vec![0; MAX_EXT_LEN + 1])
            .is_err());
    }

    #[test]
    fn trailing_bytes_rules() {
        let mut same = Capabilities::current().encode();
        same.push(0);
        assert_eq!(
            Capabilities::decode(&same),
            Err(CapabilityError::TrailingBytes)
        );
        let mut future = caps(9, KNOWN_SUITES, 0).encode();
        future.extend_from_slice(&[7, 7, 7]);
        let d = Capabilities::decode(&future).unwrap();
        assert_eq!(d.version, 9);
    }

    #[test]
    fn same_level_is_not_a_downgrade() {
        let a = Capabilities::current();
        let g = negotiate(&a, &a, &Requirements::default()).unwrap();
        assert!(!g.downgraded);
        assert!(g.reasons.is_empty());
        assert_eq!(g.best_suite(), SUITE_HYBRID_X25519_MLKEM768);
    }

    #[test]
    fn legacy_peer_degrades_visibly() {
        let g = negotiate(
            &Capabilities::current(),
            &Capabilities::legacy(),
            &Requirements::default(),
        )
        .unwrap();
        assert!(g.downgraded);
        assert_eq!(g.version, 0);
        assert_eq!(g.suites, SUITE_CLASSICAL);
        assert_eq!(g.best_suite(), SUITE_CLASSICAL);
        assert!(g.reasons.contains(&DowngradeReason::SuitesUnavailable {
            bits: SUITE_HYBRID_X25519_MLKEM768
        }));
        assert!(g.reasons.contains(&DowngradeReason::FeaturesUnavailable {
            bits: FEATURE_FRAGMENTATION
        }));
        assert!(matches!(
            g.reasons[0],
            DowngradeReason::PeerOlderVersion {
                local: 1,
                remote: 0
            }
        ));
    }

    #[test]
    fn newer_peer_with_unknown_bits_is_fine() {
        let remote = Capabilities {
            version: 77,
            suites: KNOWN_SUITES | 0xFFFF_FF00,
            features: KNOWN_FEATURES | 0x8000_0000,
            unknown: vec![9; 10],
        };
        let g = negotiate(&Capabilities::current(), &remote, &Requirements::default()).unwrap();
        assert_eq!(g.version, CAPABILITY_VERSION);
        assert_eq!(g.suites, KNOWN_SUITES);
        assert_eq!(g.features, KNOWN_FEATURES);
        assert!(!g.downgraded, "local got everything it offered");
    }

    #[test]
    fn local_with_future_bits_agrees_on_common_only() {
        let local = caps(5, KNOWN_SUITES | 1 << 20, KNOWN_FEATURES | 1 << 9);
        let g = negotiate(&local, &Capabilities::current(), &Requirements::default()).unwrap();
        assert_eq!(g.suites, KNOWN_SUITES);
        assert_eq!(g.features, KNOWN_FEATURES);
        assert!(g.downgraded);
        assert_eq!(g.version, 1);
    }

    #[test]
    fn peer_without_baseline_bit_still_gets_baseline() {
        let remote = caps(1, 0, 0);
        let g = negotiate(&Capabilities::current(), &remote, &Requirements::default()).unwrap();
        assert_eq!(g.suites, SUITE_CLASSICAL);
    }

    #[test]
    fn strict_mode_fails_closed_only_on_local_requirement() {
        let strict = Requirements {
            suites: SUITE_HYBRID_X25519_MLKEM768,
            features: 0,
        };
        let err =
            negotiate(&Capabilities::current(), &Capabilities::legacy(), &strict).unwrap_err();
        assert_eq!(
            err,
            NegotiationError::RequirementUnmet {
                missing_suites: SUITE_HYBRID_X25519_MLKEM768,
                missing_features: 0
            }
        );
        // Same strict policy against a capable peer succeeds.
        assert!(negotiate(&Capabilities::current(), &Capabilities::current(), &strict).is_ok());
        // Peer being strict is irrelevant to us: we only evaluate our own policy.
        assert!(negotiate(
            &Capabilities::legacy(),
            &Capabilities::current(),
            &Requirements::default()
        )
        .is_ok());
        let feat = Requirements {
            suites: 0,
            features: FEATURE_FRAGMENTATION,
        };
        assert!(negotiate(&Capabilities::current(), &Capabilities::legacy(), &feat).is_err());
    }

    #[test]
    fn negotiation_is_symmetric_in_result() {
        let a = Capabilities::current();
        let b = caps(0, SUITE_CLASSICAL, 0);
        let ab = negotiate(&a, &b, &Requirements::default()).unwrap();
        let ba = negotiate(&b, &a, &Requirements::default()).unwrap();
        assert_eq!(
            (ab.version, ab.suites, ab.features),
            (ba.version, ba.suites, ba.features)
        );
        assert!(ab.downgraded);
        assert!(!ba.downgraded, "legacy side got everything it offered");
    }

    #[test]
    fn binding_detects_edited_offers() {
        let a = Capabilities::current();
        let b = Capabilities::current();
        let g = negotiate(&a, &b, &Requirements::default()).unwrap();
        let honest = transcript_binding(&a, &b, &g);

        // On-path edit strips the hybrid suite from the responder's offer; the
        // initiator then computes its binding from the real offer it sent.
        let stripped = caps(1, SUITE_CLASSICAL, KNOWN_FEATURES);
        let g2 = negotiate(&a, &stripped, &Requirements::default()).unwrap();
        let tampered = transcript_binding(&a, &stripped, &g2);
        assert_ne!(honest, tampered);

        // Role order matters.
        let x = caps(1, SUITE_CLASSICAL, 0);
        let gx = negotiate(&a, &x, &Requirements::default()).unwrap();
        assert_ne!(
            transcript_binding(&a, &x, &gx),
            transcript_binding(&x, &a, &gx)
        );
        // Unknown extension bytes are bound too.
        let ext = a.clone().with_unknown(vec![1]).unwrap();
        assert_ne!(transcript_binding(&ext, &b, &g), honest);
    }
}
