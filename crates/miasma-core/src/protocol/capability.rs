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
//! # Downgrades are always visible
//!
//! A peer's offer can be weaker than ours because it is an older build, or
//! because the offer was stripped or damaged on the way. The classical baseline
//! keeps working in every case (that is the compatibility promise), but it is
//! never silent:
//!
//! * [`negotiate_offer`] takes the peer's offer as received (`None` when no
//!   capability message arrived, bytes that may not decode) and returns a
//!   [`Negotiation`]. Its [`DowngradeReport`] lists every reason, including
//!   [`DowngradeReason::OfferMissing`] and [`DowngradeReason::OfferMalformed`].
//!   Both types are `#[must_use]`: the caller has to read the report.
//!   [`negotiate_reported`] does the same for an already decoded offer.
//! * Every reported downgrade, and every refusal by local policy, also
//!   increments a process-wide counter by reason ([`downgrade_counts`]). The
//!   counters hold numbers only, no peer identifier, and the daemon status
//!   shows them.
//! * [`negotiate`] is the pure computation. It records nothing, so a caller
//!   that wants visibility uses one of the functions above.
//!
//! # Default policy
//!
//! With empty [`Requirements`] (compatibility mode, the default) a local side
//! that offers the hybrid suite and a peer that only has the classical suite
//! agree on the classical suite. That is not an error: the exchange proceeds,
//! the report carries [`DowngradeReason::SuitesUnavailable`] with the hybrid
//! bit, [`DowngradeReport::hybrid_unavailable`] is true, and the
//! `hybrid_unavailable` counter goes up. A local side that must not accept this
//! sets `Requirements::suites` to [`SUITE_HYBRID_X25519_MLKEM768`], and
//! [`negotiate`] then fails with [`NegotiationError::RequirementUnmet`] (also
//! counted as a refusal).
//!
//! What this cannot do: tell a stripped offer from a peer that never had one,
//! and detect the edit itself. Detection needs the transcript binding checked
//! over an authenticated channel; without it the report only makes the
//! outcome visible.
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

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
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
    /// No capability message arrived; the peer was treated as
    /// [`Capabilities::legacy`]. A stripped offer looks exactly like this.
    OfferMissing,
    /// A capability message arrived but did not decode; the peer was treated
    /// as [`Capabilities::legacy`].
    OfferMalformed,
}

/// Kind of a [`DowngradeReason`], without its values. Used for counting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DowngradeKind {
    OfferMissing,
    OfferMalformed,
    PeerOlderVersion,
    SuitesUnavailable,
    FeaturesUnavailable,
}

impl DowngradeReason {
    pub fn kind(&self) -> DowngradeKind {
        match self {
            Self::OfferMissing => DowngradeKind::OfferMissing,
            Self::OfferMalformed => DowngradeKind::OfferMalformed,
            Self::PeerOlderVersion { .. } => DowngradeKind::PeerOlderVersion,
            Self::SuitesUnavailable { .. } => DowngradeKind::SuitesUnavailable,
            Self::FeaturesUnavailable { .. } => DowngradeKind::FeaturesUnavailable,
        }
    }
}

impl std::fmt::Display for DowngradeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OfferMissing => write!(f, "peer sent no capability offer"),
            Self::OfferMalformed => write!(f, "peer capability offer did not decode"),
            Self::PeerOlderVersion { local, remote } => {
                write!(f, "peer capability version {remote} is older than {local}")
            }
            Self::SuitesUnavailable { bits } => {
                write!(f, "peer lacks suites {bits:#x}")
            }
            Self::FeaturesUnavailable { bits } => {
                write!(f, "peer lacks features {bits:#x}")
            }
        }
    }
}

/// Every reason a negotiation ended below what the local side offered.
///
/// The caller has to read it: show it, log it or act on it.
#[must_use = "a downgrade must be shown or logged, not dropped"]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DowngradeReport {
    reasons: Vec<DowngradeReason>,
}

impl DowngradeReport {
    /// The report for an agreed result.
    pub fn from_agreed(agreed: &Agreed) -> Self {
        Self {
            reasons: agreed.reasons.clone(),
        }
    }

    pub fn is_downgrade(&self) -> bool {
        !self.reasons.is_empty()
    }

    pub fn reasons(&self) -> &[DowngradeReason] {
        &self.reasons
    }

    /// True when the local side offered the hybrid suite and the agreed set
    /// lacks it.
    pub fn hybrid_unavailable(&self) -> bool {
        self.reasons.iter().any(|r| {
            matches!(r, DowngradeReason::SuitesUnavailable { bits }
                if bits & SUITE_HYBRID_X25519_MLKEM768 != 0)
        })
    }

    /// One line for a log or a status screen. Empty when there is no downgrade.
    pub fn summary(&self) -> String {
        self.reasons
            .iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Outcome of a reported negotiation: the agreed level and why it may be lower.
#[must_use = "read the downgrade report; a lower level must not go unnoticed"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiation {
    pub agreed: Agreed,
    pub report: DowngradeReport,
}

/// Numbers of downgrades seen by this process, by reason. No peer identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DowngradeCounts {
    /// Negotiations that ended below the local offer.
    #[serde(default)]
    pub downgraded: u64,
    /// Negotiations refused because a local requirement was not met.
    #[serde(default)]
    pub refused: u64,
    #[serde(default)]
    pub offer_missing: u64,
    #[serde(default)]
    pub offer_malformed: u64,
    #[serde(default)]
    pub peer_older_version: u64,
    #[serde(default)]
    pub suites_unavailable: u64,
    #[serde(default)]
    pub features_unavailable: u64,
    /// Subset of `suites_unavailable`: the hybrid suite was offered locally
    /// and not agreed.
    #[serde(default)]
    pub hybrid_unavailable: u64,
}

/// Counters behind [`DowngradeCounts`]. The process-wide instance is read with
/// [`downgrade_counts`]; separate instances exist for tests.
#[derive(Debug, Default)]
pub struct DowngradeCounters {
    downgraded: AtomicU64,
    refused: AtomicU64,
    offer_missing: AtomicU64,
    offer_malformed: AtomicU64,
    peer_older_version: AtomicU64,
    suites_unavailable: AtomicU64,
    features_unavailable: AtomicU64,
    hybrid_unavailable: AtomicU64,
}

impl DowngradeCounters {
    pub const fn new() -> Self {
        Self {
            downgraded: AtomicU64::new(0),
            refused: AtomicU64::new(0),
            offer_missing: AtomicU64::new(0),
            offer_malformed: AtomicU64::new(0),
            peer_older_version: AtomicU64::new(0),
            suites_unavailable: AtomicU64::new(0),
            features_unavailable: AtomicU64::new(0),
            hybrid_unavailable: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> DowngradeCounts {
        DowngradeCounts {
            downgraded: self.downgraded.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            offer_missing: self.offer_missing.load(Ordering::Relaxed),
            offer_malformed: self.offer_malformed.load(Ordering::Relaxed),
            peer_older_version: self.peer_older_version.load(Ordering::Relaxed),
            suites_unavailable: self.suites_unavailable.load(Ordering::Relaxed),
            features_unavailable: self.features_unavailable.load(Ordering::Relaxed),
            hybrid_unavailable: self.hybrid_unavailable.load(Ordering::Relaxed),
        }
    }

    fn count_reason(&self, reason: &DowngradeReason) {
        let slot = match reason.kind() {
            DowngradeKind::OfferMissing => &self.offer_missing,
            DowngradeKind::OfferMalformed => &self.offer_malformed,
            DowngradeKind::PeerOlderVersion => &self.peer_older_version,
            DowngradeKind::SuitesUnavailable => &self.suites_unavailable,
            DowngradeKind::FeaturesUnavailable => &self.features_unavailable,
        };
        slot.fetch_add(1, Ordering::Relaxed);
        if matches!(reason, DowngradeReason::SuitesUnavailable { bits }
            if bits & SUITE_HYBRID_X25519_MLKEM768 != 0)
        {
            self.hybrid_unavailable.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record(&self, report: &DowngradeReport) {
        if !report.is_downgrade() {
            return;
        }
        self.downgraded.fetch_add(1, Ordering::Relaxed);
        for reason in report.reasons() {
            self.count_reason(reason);
        }
    }

    fn record_refusal(&self, defect: Option<&DowngradeReason>) {
        self.refused.fetch_add(1, Ordering::Relaxed);
        if let Some(reason) = defect {
            self.count_reason(reason);
        }
    }
}

static PROCESS_DOWNGRADES: DowngradeCounters = DowngradeCounters::new();

/// Downgrade counters of this process, for the daemon status.
pub fn downgrade_counts() -> DowngradeCounts {
    PROCESS_DOWNGRADES.snapshot()
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
///
/// This is the pure computation: it records nothing. Use [`negotiate_offer`]
/// or [`negotiate_reported`] to get a [`DowngradeReport`] and the counters.
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

/// Resolve the peer's offer as received. `None` (no capability message) and
/// bytes that do not decode both give [`Capabilities::legacy`], together with
/// the reason, so the caller cannot take the fallback for a real offer.
pub fn resolve_remote(wire: Option<&[u8]>) -> (Capabilities, Option<DowngradeReason>) {
    match wire {
        None => (Capabilities::legacy(), Some(DowngradeReason::OfferMissing)),
        Some(bytes) => match Capabilities::decode(bytes) {
            Ok(caps) => (caps, None),
            Err(_) => (
                Capabilities::legacy(),
                Some(DowngradeReason::OfferMalformed),
            ),
        },
    }
}

/// [`negotiate`] with the downgrade made visible: the result carries a
/// [`DowngradeReport`] and the process-wide counters are updated.
pub fn negotiate_reported(
    local: &Capabilities,
    remote: &Capabilities,
    require: &Requirements,
) -> Result<Negotiation, NegotiationError> {
    negotiate_reported_with(&PROCESS_DOWNGRADES, local, remote, require)
}

/// [`negotiate_reported`] counting into the given counters.
pub fn negotiate_reported_with(
    counters: &DowngradeCounters,
    local: &Capabilities,
    remote: &Capabilities,
    require: &Requirements,
) -> Result<Negotiation, NegotiationError> {
    match negotiate(local, remote, require) {
        Ok(agreed) => {
            let report = DowngradeReport::from_agreed(&agreed);
            counters.record(&report);
            Ok(Negotiation { agreed, report })
        }
        Err(e) => {
            counters.record_refusal(None);
            Err(e)
        }
    }
}

/// Negotiate against the peer's offer as it arrived: `None` when no capability
/// message came, otherwise the raw bytes. A missing or malformed offer is
/// negotiated as [`Capabilities::legacy`] and reported as such.
pub fn negotiate_offer(
    local: &Capabilities,
    remote_wire: Option<&[u8]>,
    require: &Requirements,
) -> Result<Negotiation, NegotiationError> {
    negotiate_offer_with(&PROCESS_DOWNGRADES, local, remote_wire, require)
}

/// [`negotiate_offer`] counting into the given counters.
pub fn negotiate_offer_with(
    counters: &DowngradeCounters,
    local: &Capabilities,
    remote_wire: Option<&[u8]>,
    require: &Requirements,
) -> Result<Negotiation, NegotiationError> {
    let (remote, defect) = resolve_remote(remote_wire);
    match negotiate(local, &remote, require) {
        Ok(mut agreed) => {
            if let Some(reason) = defect {
                // The root cause comes first.
                agreed.reasons.insert(0, reason);
                agreed.downgraded = true;
            }
            let report = DowngradeReport::from_agreed(&agreed);
            counters.record(&report);
            Ok(Negotiation { agreed, report })
        }
        Err(e) => {
            counters.record_refusal(defect.as_ref());
            Err(e)
        }
    }
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
    const FROZEN_BINDING: &str = "96ad53b290d8ade644d3a0d42472489e232285f9f150f85051f24aef711f7a33";

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

    // ── Visible downgrades ───────────────────────────────────────────────────

    #[test]
    fn stripped_offer_is_reported_and_counted() {
        let counters = DowngradeCounters::new();
        let n = negotiate_offer_with(
            &counters,
            &Capabilities::current(),
            None,
            &Requirements::default(),
        )
        .unwrap();
        // Classical still works.
        assert_eq!(n.agreed.best_suite(), SUITE_CLASSICAL);
        assert!(n.agreed.downgraded);
        assert!(n.report.is_downgrade());
        assert_eq!(n.report.reasons()[0], DowngradeReason::OfferMissing);
        assert!(n.report.hybrid_unavailable());
        assert!(n.report.summary().contains("no capability offer"));
        let c = counters.snapshot();
        assert_eq!(c.downgraded, 1);
        assert_eq!(c.offer_missing, 1);
        assert_eq!(c.offer_malformed, 0);
        assert_eq!(c.hybrid_unavailable, 1);
        assert_eq!(c.refused, 0);
    }

    #[test]
    fn malformed_offer_is_reported_and_counted_apart_from_a_missing_one() {
        let counters = DowngradeCounters::new();
        for bytes in [&[][..], &[1, 2, 3][..], &[0xFF; 40][..]] {
            let n = negotiate_offer_with(
                &counters,
                &Capabilities::current(),
                Some(bytes),
                &Requirements::default(),
            )
            .unwrap();
            assert_eq!(n.report.reasons()[0], DowngradeReason::OfferMalformed);
            assert_eq!(n.agreed.best_suite(), SUITE_CLASSICAL);
        }
        let c = counters.snapshot();
        assert_eq!(
            (c.offer_malformed, c.offer_missing, c.downgraded),
            (3, 0, 3)
        );
    }

    #[test]
    fn a_valid_full_offer_is_not_a_downgrade_and_counts_nothing() {
        let counters = DowngradeCounters::new();
        let wire = Capabilities::current().encode();
        let n = negotiate_offer_with(
            &counters,
            &Capabilities::current(),
            Some(&wire),
            &Requirements::default(),
        )
        .unwrap();
        assert!(!n.report.is_downgrade());
        assert!(!n.agreed.downgraded);
        assert_eq!(n.agreed.best_suite(), SUITE_HYBRID_X25519_MLKEM768);
        assert_eq!(counters.snapshot(), DowngradeCounts::default());
    }

    #[test]
    fn default_policy_hybrid_local_classical_peer_is_visible_not_an_error() {
        let counters = DowngradeCounters::new();
        let classical = caps(CAPABILITY_VERSION, SUITE_CLASSICAL, KNOWN_FEATURES).encode();
        let n = negotiate_reported_with(
            &counters,
            &Capabilities::current(),
            &Capabilities::decode(&classical).unwrap(),
            &Requirements::default(),
        )
        .unwrap();
        assert_eq!(n.agreed.best_suite(), SUITE_CLASSICAL);
        assert!(n.report.hybrid_unavailable());
        assert_eq!(
            n.report.reasons(),
            &[DowngradeReason::SuitesUnavailable {
                bits: SUITE_HYBRID_X25519_MLKEM768
            }]
        );
        let c = counters.snapshot();
        assert_eq!(
            (
                c.downgraded,
                c.suites_unavailable,
                c.hybrid_unavailable,
                c.refused
            ),
            (1, 1, 1, 0)
        );
    }

    #[test]
    fn strict_refusal_is_counted_including_the_offer_defect() {
        let counters = DowngradeCounters::new();
        let strict = Requirements {
            suites: SUITE_HYBRID_X25519_MLKEM768,
            features: 0,
        };
        assert!(negotiate_offer_with(&counters, &Capabilities::current(), None, &strict).is_err());
        assert!(negotiate_reported_with(
            &counters,
            &Capabilities::current(),
            &Capabilities::legacy(),
            &strict
        )
        .is_err());
        let c = counters.snapshot();
        assert_eq!(c.refused, 2);
        assert_eq!(c.offer_missing, 1);
        assert_eq!(c.downgraded, 0, "a refusal is not an accepted downgrade");
    }

    #[test]
    fn counters_hold_numbers_only() {
        let counters = DowngradeCounters::new();
        let _ = negotiate_offer_with(
            &counters,
            &Capabilities::current(),
            None,
            &Requirements::default(),
        )
        .unwrap();
        let json = serde_json::to_value(counters.snapshot()).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.values().all(|v| v.is_u64()), "{json}");
        // An older status without the field still parses.
        let back: DowngradeCounts = serde_json::from_str("{}").unwrap();
        assert_eq!(back, DowngradeCounts::default());
    }

    #[test]
    fn process_counters_follow_the_reported_calls() {
        // Other tests in this process may add to the counters at the same
        // time, so only a lower bound can be asserted.
        let before = downgrade_counts();
        let n = negotiate_offer(&Capabilities::current(), None, &Requirements::default()).unwrap();
        assert!(n.report.is_downgrade());
        let after = downgrade_counts();
        assert!(after.downgraded > before.downgraded);
        assert!(after.offer_missing > before.offer_missing);
    }
}
