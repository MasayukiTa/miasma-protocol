//! The transfer manifest — the "index" a receiver gets before any data.
//!
//! Analogous to a `.torrent`: it lists every piece (shard) of every segment by
//! ID, so the receiver can verify each piece the moment it arrives instead of
//! discovering a bad one only after RS decode and AEAD fail.
//!
//! It is **not** an independent root of trust. The root remains the whole-file
//! MID, checked at the end. A lying manifest can waste bandwidth; it cannot
//! make a wrong file pass the final check.
//!
//! # Placement
//!
//! The manifest rides as a framed trailer appended to the signed DHT record
//! value, after the bincode `DhtRecord`:
//!
//! ```text
//! bincode(DhtRecord) || "MNFT" || version:u8 || len:u32-le || bincode(TransferManifest)
//! ```
//!
//! `bincode::deserialize` ignores trailing bytes, so a reader that predates this
//! module still decodes the record. The record and its manifest also arrive in
//! one signed PUT/GET, so there is never a window where one exists without the
//! other.

use serde::{Deserialize, Serialize};

use super::protection::Protection;
use crate::{
    crypto::hash::ContentId,
    network::types::{DhtRecord, MAX_SEGMENTS},
    pipeline::DissolutionParams,
    share::MiasmaShare,
    MiasmaError,
};

/// Trailer magic.
pub const TRAILER_MAGIC: &[u8; 4] = b"MNFT";
/// Manifest format version.
///
/// 2: a piece ID is the full-share commitment ([`MiasmaShare::piece_commitment`]),
/// not `BLAKE3(shard_data)`. Version 1 manifests are refused (beta: no second
/// format is kept), see [`TransferManifest::validate`].
pub const MANIFEST_VERSION: u8 = 2;
/// Largest plaintext segment a manifest may declare: the publisher never
/// exceeds `DEFAULT_SEGMENT_SIZE` (64 MiB). A receiver sizes its per-segment
/// decode buffers from this untrusted field, so it is bounded.
pub const MAX_SEGMENT_SIZE: u32 = crate::dissolution::DEFAULT_SEGMENT_SIZE as u32;
/// Hard cap on an encoded manifest, enforced on both encode and decode.
///
/// 100 GiB at `n = 20` is ~1.1 MB; this leaves room for `n` up to 255 at that
/// size while still bounding what an untrusted record can make a node parse.
pub const MANIFEST_MAX_BYTES: usize = 8 * 1024 * 1024;

const TRAILER_HEADER_LEN: usize = 4 + 1 + 4;

/// One piece's ID: the commitment over the whole share, see
/// [`MiasmaShare::piece_commitment`] (it covers `key_share` and `nonce`, which
/// `MiasmaShare::shard_hash` does not).
pub type PieceId = [u8; 32];

/// Everything the receiver needs to know about one segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentEntry {
    pub index: u32,
    /// Plaintext bytes in this segment.
    pub plaintext_len: u32,
    /// `BLAKE3(plaintext segment)`: lets a segment be verified on its own, which
    /// is what makes resume possible without trusting a partial file.
    pub plain_hash: [u8; 32],
    /// One ID per shard slot, indexed by `slot_index`; length is `total_shards`.
    pub piece_ids: Vec<PieceId>,
}

impl SegmentEntry {
    /// Build an entry from a freshly dissolved segment.
    ///
    /// `shares` may be in any order; they must be exactly the segment's
    /// `total_shards` shares with distinct slot indexes `0..n`.
    pub fn from_dissolved(
        index: u32,
        mid: &ContentId,
        plaintext: &[u8],
        shares: &[MiasmaShare],
    ) -> Result<Self, MiasmaError> {
        let n = shares.len();
        let mut piece_ids: Vec<Option<PieceId>> = vec![None; n];
        for share in shares {
            let slot = share.slot_index as usize;
            let cell = piece_ids.get_mut(slot).ok_or_else(|| {
                MiasmaError::InvalidManifest(format!("slot {slot} out of range for {n} shares"))
            })?;
            if share.segment_index != index {
                return Err(MiasmaError::InvalidManifest(format!(
                    "share of segment {} listed under segment {index}",
                    share.segment_index
                )));
            }
            if cell.replace(share.piece_commitment(mid)).is_some() {
                return Err(MiasmaError::InvalidManifest(format!(
                    "duplicate shard slot {slot} in segment {index}"
                )));
            }
        }
        // Every slot 0..n was filled exactly once (n shares, n distinct in-range slots).
        let piece_ids = piece_ids
            .into_iter()
            .map(|id| id.expect("distinct in-range slots fill every cell"))
            .collect();
        Ok(Self {
            index,
            plaintext_len: u32::try_from(plaintext.len())
                .map_err(|_| MiasmaError::InvalidManifest("segment larger than u32::MAX".into()))?,
            plain_hash: *blake3::hash(plaintext).as_bytes(),
            piece_ids,
        })
    }
}

/// The index of one transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferManifest {
    pub version: u8,
    /// Must equal the carrying record's `mid_digest`.
    pub mid: [u8; 32],
    pub data_shards: u8,
    pub total_shards: u8,
    pub segment_size: u32,
    pub total_bytes: u64,
    pub protection: Protection,
    /// Ordered by `index`, contiguous from 0.
    pub segments: Vec<SegmentEntry>,
}

impl TransferManifest {
    pub fn new(
        mid: &ContentId,
        params: DissolutionParams,
        segment_size: u32,
        total_bytes: u64,
        protection: Protection,
    ) -> Self {
        Self {
            version: MANIFEST_VERSION,
            mid: *mid.as_bytes(),
            data_shards: params.data_shards as u8,
            total_shards: params.total_shards as u8,
            segment_size,
            total_bytes,
            protection,
            segments: Vec::new(),
        }
    }

    pub fn params(&self) -> DissolutionParams {
        DissolutionParams {
            data_shards: self.data_shards as usize,
            total_shards: self.total_shards as usize,
        }
    }

    /// Append the next segment. Indexes must arrive in order.
    pub fn push_segment(&mut self, entry: SegmentEntry) -> Result<(), MiasmaError> {
        if entry.index as usize != self.segments.len() {
            return Err(MiasmaError::InvalidManifest(format!(
                "segment {} pushed out of order (expected {})",
                entry.index,
                self.segments.len()
            )));
        }
        self.segments.push(entry);
        Ok(())
    }

    /// Internal consistency. A manifest that fails this must never be acted on:
    /// it comes from the network.
    pub fn validate(&self) -> Result<(), MiasmaError> {
        let bad = |m: String| Err(MiasmaError::InvalidManifest(m));
        if self.version != MANIFEST_VERSION {
            return bad(unsupported_version_message(self.version));
        }
        let (k, n) = (self.data_shards as usize, self.total_shards as usize);
        if k == 0 || n < k {
            return bad(format!("invalid shard counts k={k}, n={n}"));
        }
        if self.segment_size == 0 {
            return bad("segment_size is zero".into());
        }
        if self.segment_size > MAX_SEGMENT_SIZE {
            return bad(format!(
                "segment_size {} exceeds the limit {MAX_SEGMENT_SIZE}",
                self.segment_size
            ));
        }
        if self.segments.len() > MAX_SEGMENTS as usize {
            return bad(format!(
                "{} segments listed, limit {MAX_SEGMENTS}",
                self.segments.len()
            ));
        }
        if let Protection::Password(p) = &self.protection {
            p.validate()?;
        }

        // An empty file still has exactly one (empty) segment, as in publish.
        let expected_segments = if self.total_bytes == 0 {
            1
        } else {
            self.total_bytes.div_ceil(self.segment_size as u64)
        };
        if self.segments.len() as u64 != expected_segments {
            return bad(format!(
                "{} segments listed, {} expected for {} bytes at segment_size {}",
                self.segments.len(),
                expected_segments,
                self.total_bytes,
                self.segment_size
            ));
        }

        let mut sum: u64 = 0;
        for (i, seg) in self.segments.iter().enumerate() {
            if seg.index as usize != i {
                return bad(format!("segment at position {i} has index {}", seg.index));
            }
            if seg.piece_ids.len() != n {
                return bad(format!(
                    "segment {i} lists {} pieces, expected n={n}",
                    seg.piece_ids.len()
                ));
            }
            if seg.plaintext_len > self.segment_size {
                return bad(format!("segment {i} longer than segment_size"));
            }
            // Only the last segment may be short.
            if i + 1 < self.segments.len() && seg.plaintext_len != self.segment_size {
                return bad(format!("non-final segment {i} is short"));
            }
            sum += seg.plaintext_len as u64;
        }
        if sum != self.total_bytes {
            return bad(format!(
                "segment lengths sum to {sum}, total_bytes is {}",
                self.total_bytes
            ));
        }
        Ok(())
    }

    /// The piece ID expected for `(segment, slot)`, if listed.
    pub fn expected_piece(&self, segment: u32, slot: u16) -> Option<&PieceId> {
        self.segments
            .get(segment as usize)?
            .piece_ids
            .get(slot as usize)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, MiasmaError> {
        let bytes =
            bincode::serialize(self).map_err(|e| MiasmaError::Serialization(e.to_string()))?;
        if bytes.len() > MANIFEST_MAX_BYTES {
            return Err(MiasmaError::InvalidManifest(format!(
                "manifest is {} bytes, limit {MANIFEST_MAX_BYTES}",
                bytes.len()
            )));
        }
        Ok(bytes)
    }

    /// Decode *and validate*. Untrusted input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MiasmaError> {
        if bytes.len() > MANIFEST_MAX_BYTES {
            return Err(MiasmaError::InvalidManifest(format!(
                "manifest is {} bytes, limit {MANIFEST_MAX_BYTES}",
                bytes.len()
            )));
        }
        let manifest: Self = bincode::deserialize(bytes)
            .map_err(|e| MiasmaError::InvalidManifest(format!("decode: {e}")))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Stable identity of this exact manifest. A resume journal records it so a
    /// journal is never applied to a different (re-published) manifest.
    pub fn manifest_hash(&self) -> Result<[u8; 32], MiasmaError> {
        Ok(*blake3::hash(&self.to_bytes()?).as_bytes())
    }

    /// The framed trailer to append to a serialized `DhtRecord`.
    pub fn encode_trailer(&self) -> Result<Vec<u8>, MiasmaError> {
        let payload = self.to_bytes()?;
        let mut out = Vec::with_capacity(TRAILER_HEADER_LEN + payload.len());
        out.extend_from_slice(TRAILER_MAGIC);
        out.push(MANIFEST_VERSION);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }
}

fn unsupported_version_message(found: u8) -> String {
    if found < MANIFEST_VERSION {
        format!(
            "manifest version {found} is no longer supported (this build reads version \
             {MANIFEST_VERSION}: piece IDs now commit to the whole share); ask the sender to \
             publish the file again"
        )
    } else {
        format!(
            "manifest version {found} is newer than this build supports ({MANIFEST_VERSION}); \
             update Miasma"
        )
    }
}

/// Serialize `record` followed by `manifest`'s trailer, as the signed value.
pub fn encode_record_value(
    record: &DhtRecord,
    manifest: Option<&TransferManifest>,
) -> Result<Vec<u8>, MiasmaError> {
    // Never publish a record the receivers' own validation would refuse.
    record.validate()?;
    let mut value =
        bincode::serialize(record).map_err(|e| MiasmaError::Serialization(e.to_string()))?;
    if let Some(m) = manifest {
        if m.mid != record.mid_digest {
            return Err(MiasmaError::InvalidManifest(
                "manifest MID does not match the record it rides on".into(),
            ));
        }
        value.extend_from_slice(&m.encode_trailer()?);
    }
    Ok(value)
}

/// Decode a record value into `(record, optional manifest)`.
///
/// A value with no trailer is a legacy record and yields `(record, None)`.
/// A value whose trailer is present but malformed is an **error**, not a
/// silent downgrade: otherwise stripping or corrupting the trailer would turn
/// a protected transfer into an unprotected-looking one.
pub fn decode_record_value(
    value: &[u8],
) -> Result<(DhtRecord, Option<TransferManifest>), MiasmaError> {
    let mut cursor = std::io::Cursor::new(value);
    let record: DhtRecord = bincode::deserialize_from(&mut cursor)
        .map_err(|e| MiasmaError::Serialization(format!("record: {e}")))?;
    let rest = &value[cursor.position() as usize..];
    if rest.is_empty() {
        return Ok((record, None));
    }

    if rest.len() < TRAILER_HEADER_LEN || &rest[..4] != TRAILER_MAGIC {
        return Err(MiasmaError::InvalidManifest(
            "unrecognized data after the record".into(),
        ));
    }
    if rest[4] != MANIFEST_VERSION {
        return Err(MiasmaError::InvalidManifest(unsupported_version_message(
            rest[4],
        )));
    }
    let len = u32::from_le_bytes(rest[5..9].try_into().expect("4 bytes")) as usize;
    let payload = &rest[TRAILER_HEADER_LEN..];
    if payload.len() != len {
        return Err(MiasmaError::InvalidManifest(format!(
            "trailer declares {len} bytes but {} follow",
            payload.len()
        )));
    }
    let manifest = TransferManifest::from_bytes(payload)?;
    if manifest.mid != record.mid_digest {
        return Err(MiasmaError::InvalidManifest(
            "manifest MID does not match its record".into(),
        ));
    }
    Ok((record, Some(manifest)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dissolution::dissolve_segment, transfer::protection::PasswordProtection};

    fn params() -> DissolutionParams {
        DissolutionParams {
            data_shards: 4,
            total_shards: 6,
        }
    }

    fn mid() -> ContentId {
        ContentId::compute(b"whole file", &params().to_param_bytes())
    }

    /// A consistent manifest over `segs` segments of `seg_size` bytes (last one
    /// `last` bytes), built from real dissolved shares.
    fn build(seg_size: u32, segs: u32, last: u32) -> TransferManifest {
        let total = seg_size as u64 * (segs as u64 - 1) + last as u64;
        let mut m = TransferManifest::new(&mid(), params(), seg_size, total, Protection::None);
        for i in 0..segs {
            let len = (if i + 1 == segs { last } else { seg_size }) as usize;
            let data = vec![i as u8 + 1; len];
            let (_, shares) = dissolve_segment(&data, &mid(), i, 0, params()).unwrap();
            m.push_segment(SegmentEntry::from_dissolved(i, &mid(), &data, &shares).unwrap())
                .unwrap();
        }
        m
    }

    fn record(mid_digest: [u8; 32]) -> DhtRecord {
        DhtRecord {
            mid_digest,
            data_shards: 4,
            total_shards: 6,
            version: 1,
            locations: vec![],
            published_at: 1,
        }
    }

    #[test]
    fn piece_ids_are_the_piece_commitments_indexed_by_slot() {
        let data = vec![5u8; 300];
        let (_, mut shares) = dissolve_segment(&data, &mid(), 0, 0, params()).unwrap();
        shares.reverse(); // arrival order must not matter
        let entry = SegmentEntry::from_dissolved(0, &mid(), &data, &shares).unwrap();
        assert_eq!(entry.piece_ids.len(), 6);
        for s in &shares {
            assert_eq!(
                entry.piece_ids[s.slot_index as usize],
                s.piece_commitment(&mid())
            );
        }
        assert_eq!(entry.plain_hash, *blake3::hash(&data).as_bytes());
    }

    #[test]
    fn a_consistent_manifest_validates_and_round_trips() {
        let m = build(256, 3, 100);
        m.validate().unwrap();
        let bytes = m.to_bytes().unwrap();
        assert_eq!(TransferManifest::from_bytes(&bytes).unwrap(), m);
        assert_eq!(m.manifest_hash().unwrap(), m.manifest_hash().unwrap());
    }

    #[test]
    fn every_kind_of_inconsistency_is_rejected() {
        let good = build(256, 3, 100);

        let mut m = good.clone();
        m.total_bytes += 1;
        assert!(m.validate().is_err(), "total_bytes does not match segments");

        let mut m = good.clone();
        m.segments[1].piece_ids.pop();
        assert!(m.validate().is_err(), "wrong piece count");

        let mut m = good.clone();
        m.segments[0].plaintext_len -= 1;
        assert!(m.validate().is_err(), "non-final segment is short");

        let mut m = good.clone();
        m.segments[2].index = 7;
        assert!(m.validate().is_err(), "segment index out of place");

        let mut m = good.clone();
        m.segments.pop();
        assert!(m.validate().is_err(), "segment count vs total_bytes");

        let mut m = good.clone();
        m.data_shards = 0;
        assert!(m.validate().is_err(), "k == 0");

        let mut m = good.clone();
        m.total_shards = m.data_shards - 1;
        assert!(m.validate().is_err(), "n < k");

        let mut m = good.clone();
        m.segment_size = 0;
        assert!(m.validate().is_err(), "segment_size == 0");

        let mut m = good.clone();
        m.version = 9;
        assert!(m.validate().is_err(), "unknown version");
    }

    #[test]
    fn segments_must_be_pushed_in_order() {
        let mut m = TransferManifest::new(&mid(), params(), 256, 512, Protection::None);
        let data = vec![1u8; 256];
        let (_, shares) = dissolve_segment(&data, &mid(), 1, 0, params()).unwrap();
        let entry = SegmentEntry::from_dissolved(1, &mid(), &data, &shares).unwrap();
        assert!(m.push_segment(entry).is_err());
    }

    #[test]
    fn an_empty_file_has_one_empty_segment() {
        let mut m = TransferManifest::new(&mid(), params(), 256, 0, Protection::None);
        let (_, shares) = dissolve_segment(&[], &mid(), 0, 0, params()).unwrap();
        m.push_segment(SegmentEntry::from_dissolved(0, &mid(), &[], &shares).unwrap())
            .unwrap();
        m.validate().unwrap();
    }

    #[test]
    fn duplicate_or_out_of_range_slots_are_rejected() {
        let data = vec![1u8; 100];
        let (_, mut shares) = dissolve_segment(&data, &mid(), 0, 0, params()).unwrap();
        shares[1].slot_index = 0; // duplicate slot 0
        assert!(SegmentEntry::from_dissolved(0, &mid(), &data, &shares).is_err());

        let (_, mut shares) = dissolve_segment(&data, &mid(), 0, 0, params()).unwrap();
        shares[1].slot_index = 99;
        assert!(SegmentEntry::from_dissolved(0, &mid(), &data, &shares).is_err());
    }

    #[test]
    fn the_trailer_rides_a_record_and_a_pre_manifest_decoder_still_reads_it() {
        let m = build(256, 2, 50);
        let rec = record(m.mid);
        let value = encode_record_value(&rec, Some(&m)).unwrap();

        // The decoder shipped before this module: plain bincode of DhtRecord.
        let legacy: DhtRecord = bincode::deserialize(&value).unwrap();
        assert_eq!(legacy.mid_digest, rec.mid_digest);
        assert_eq!(legacy.published_at, rec.published_at);

        // The new decoder recovers both halves.
        let (r2, m2) = decode_record_value(&value).unwrap();
        assert_eq!(r2.mid_digest, rec.mid_digest);
        assert_eq!(m2.unwrap(), m);
    }

    #[test]
    fn a_legacy_record_without_a_trailer_decodes_to_no_manifest() {
        let rec = record([7u8; 32]);
        let value = bincode::serialize(&rec).unwrap();
        let (r, m) = decode_record_value(&value).unwrap();
        assert_eq!(r.mid_digest, rec.mid_digest);
        assert!(m.is_none());
    }

    #[test]
    fn a_damaged_trailer_is_an_error_never_a_silent_downgrade() {
        let m = build(256, 2, 50);
        let rec = record(m.mid);
        let good = encode_record_value(&rec, Some(&m)).unwrap();
        let rec_len = bincode::serialize(&rec).unwrap().len();

        // Truncated payload.
        assert!(decode_record_value(&good[..good.len() - 1]).is_err());
        // Bad magic.
        let mut bad = good.clone();
        bad[rec_len] = b'X';
        assert!(decode_record_value(&bad).is_err());
        // Unknown trailer version.
        let mut bad = good.clone();
        bad[rec_len + 4] = 99;
        assert!(decode_record_value(&bad).is_err());
        // Length field lies.
        let mut bad = good.clone();
        bad[rec_len + 5] ^= 0xFF;
        assert!(decode_record_value(&bad).is_err());
        // Stray bytes after a record that are not a trailer.
        let mut bad = bincode::serialize(&rec).unwrap();
        bad.extend_from_slice(b"junk");
        assert!(decode_record_value(&bad).is_err());
        // Trailing garbage after a valid manifest.
        let mut bad = good.clone();
        bad.push(0);
        assert!(decode_record_value(&bad).is_err());
    }

    #[test]
    fn a_manifest_for_a_different_mid_is_refused() {
        let m = build(256, 2, 50);
        let other = record([0xEE; 32]);
        assert!(encode_record_value(&other, Some(&m)).is_err());

        // And on decode, if someone splices a valid trailer onto another record.
        let trailer = m.encode_trailer().unwrap();
        let mut value = bincode::serialize(&other).unwrap();
        value.extend_from_slice(&trailer);
        assert!(decode_record_value(&value).is_err());
    }

    #[test]
    fn a_password_manifest_carries_only_public_parameters() {
        let pw = crate::transfer::protection::random_test_password();
        let (prot, _key) = PasswordProtection::create_with_cost(&pw, 64, 1, 1).unwrap();
        let mut m = build(256, 2, 50);
        m.protection = Protection::Password(prot);
        m.validate().unwrap();
        let bytes = m.to_bytes().unwrap();
        assert!(
            !bytes.windows(pw.len()).any(|w| w == pw.as_bytes()),
            "the password must not appear in the encoded manifest"
        );
    }

    #[test]
    fn hostile_argon2_cost_in_a_manifest_fails_validation() {
        let pw = crate::transfer::protection::random_test_password();
        let (mut prot, _) = PasswordProtection::create_with_cost(&pw, 64, 1, 1).unwrap();
        prot.m_kib = 4 * 1024 * 1024;
        let mut m = build(256, 2, 50);
        m.protection = Protection::Password(prot);
        assert!(m.validate().is_err());
    }

    #[test]
    fn hundred_gib_manifest_at_default_redundancy_is_about_a_megabyte() {
        // 1600 segments x 20 pieces, without dissolving anything.
        let params = DissolutionParams::default();
        let seg = crate::dissolution::DEFAULT_SEGMENT_SIZE as u32;
        let total: u64 = 100 * 1024 * 1024 * 1024;
        let mut m = TransferManifest::new(&mid(), params, seg, total, Protection::None);
        for i in 0..1600u32 {
            m.push_segment(SegmentEntry {
                index: i,
                plaintext_len: seg,
                plain_hash: [i as u8; 32],
                piece_ids: vec![[i as u8; 32]; params.total_shards],
            })
            .unwrap();
        }
        m.validate().unwrap();
        let len = m.to_bytes().unwrap().len();
        println!("100 GiB manifest at k=10,n=20: {len} bytes");
        assert!(len < 2 * 1024 * 1024, "manifest is {len} bytes");
        assert!(len < MANIFEST_MAX_BYTES);
    }

    /// The whole signed value — worst-case record *plus* manifest — for a
    /// 100 GiB file must stay under the DHT's hard cap. The record half is built
    /// the way `network::node`'s own 100 GiB budget test builds it (four dial
    /// addresses per holder, deliberately more than the normal one), so this is
    /// that test with the manifest added.
    #[test]
    fn hundred_gib_record_plus_manifest_fits_the_dht_value_cap() {
        use crate::network::{
            node::{DHT_INNER_RECORD_MAX_BYTES, DHT_RECORD_MAX_VALUE_BYTES},
            sybil::SignedDhtRecord,
            types::ShardLocation,
        };

        let params = DissolutionParams::default();
        let seg = crate::dissolution::DEFAULT_SEGMENT_SIZE as u32;
        let total: u64 = 100 * 1024 * 1024 * 1024;
        let segments = 1600u32;

        let addrs = vec![
            "/ip4/203.0.113.10/udp/4001/quic-v1".to_string(),
            "/ip4/203.0.113.10/tcp/4001".to_string(),
            "/ip6/2001:db8::10/udp/4001/quic-v1".to_string(),
            "/dns4/node.example.net/tcp/443/wss".to_string(),
        ];
        let peer = libp2p::PeerId::random().to_bytes();
        let mut locations = Vec::new();
        for s in 0..segments {
            for slot in 0..params.total_shards {
                locations.push(ShardLocation {
                    peer_id_bytes: peer.clone(),
                    shard_index: slot as u16,
                    segment_index: s,
                    addrs: addrs.clone(),
                });
            }
        }
        let the_mid = ContentId::compute(b"budget", &params.to_param_bytes());
        let mid_digest = *the_mid.as_bytes();
        let rec = DhtRecord {
            mid_digest,
            data_shards: params.data_shards as u8,
            total_shards: params.total_shards as u8,
            version: 1,
            locations,
            published_at: 0,
        };

        let mut m = TransferManifest::new(&the_mid, params, seg, total, Protection::None);
        for i in 0..segments {
            m.push_segment(SegmentEntry {
                index: i,
                plaintext_len: seg,
                plain_hash: [i as u8; 32],
                piece_ids: vec![[i as u8; 32]; params.total_shards],
            })
            .unwrap();
        }

        let value = encode_record_value(&rec, Some(&m)).unwrap();
        let record_only = bincode::serialize(&rec).unwrap().len();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x5A; 32]);
        let envelope = bincode::serialize(&SignedDhtRecord::sign(
            rec.dht_key(),
            value.clone(),
            &signing_key,
        ))
        .unwrap();
        println!(
            "100 GiB: record {record_only} B + manifest {} B = value {} B, envelope {} B \
             (inner cap {DHT_INNER_RECORD_MAX_BYTES}, value cap {DHT_RECORD_MAX_VALUE_BYTES})",
            value.len() - record_only,
            value.len(),
            envelope.len()
        );
        assert!(value.len() < DHT_INNER_RECORD_MAX_BYTES);
        assert!(envelope.len() < DHT_RECORD_MAX_VALUE_BYTES);

        // And it still decodes, both ways.
        let (r2, m2) = decode_record_value(&value).unwrap();
        assert_eq!(r2.locations.len(), 32_000);
        assert_eq!(m2.unwrap().segments.len(), 1600);
        let legacy: DhtRecord = bincode::deserialize(&value).unwrap();
        assert_eq!(legacy.locations.len(), 32_000);
    }
}
