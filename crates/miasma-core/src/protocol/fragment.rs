//! Handshake fragment framing and bounded reassembly.
//!
//! Fragmentation exists for transport robustness and bounded memory only. It
//! does not change what the handshake means: authentication is done by the
//! caller over the reassembled logical message.
//!
//! # Wire format (big-endian)
//!
//! ```text
//! version        u8    must be FRAGMENT_VERSION
//! handshake_id   u64
//! suite          u16
//! fragment_index u16   0-based, < fragment_count
//! fragment_count u16   >= 1
//! total_len      u32   length of the whole logical message, > 0
//! payload_len    u32   length of this fragment's payload, > 0
//! payload        payload_len bytes (exactly the rest of the frame)
//! ```
//!
//! # Versions
//!
//! A frame with a different `version` byte cannot be parsed by this build and
//! is reported as [`FragmentError::UnsupportedVersion`]. Callers must only
//! send fragments to a peer after capability negotiation agreed on
//! `FEATURE_FRAGMENTATION`; an unsupported frame is then a clean "peer uses
//! something we did not agree on" signal, not a reason to drop other traffic.
//!
//! # Time
//!
//! The reassembler never reads a clock. Every call that needs time takes
//! `now_ms: u64` from the caller.

use std::collections::HashMap;

use thiserror::Error;

pub const FRAGMENT_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 1 + 8 + 2 + 2 + 2 + 4 + 4;

/// Absolute limits enforced by the decoder regardless of reassembler config.
pub const ABS_MAX_TOTAL_LEN: u32 = 1 << 20;
pub const ABS_MAX_FRAGMENTS: u16 = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FragmentError {
    #[error("fragment truncated")]
    Truncated,
    #[error("unsupported fragment version {0}")]
    UnsupportedVersion(u8),
    #[error("fragment count is zero")]
    ZeroCount,
    #[error("fragment index {index} out of range for count {count}")]
    IndexOutOfRange { index: u16, count: u16 },
    #[error("total length is zero or above the limit")]
    BadTotalLen,
    #[error("empty or inconsistent payload length")]
    BadPayloadLen,
    #[error("fragment count above the limit")]
    TooManyFragments,
    #[error("trailing bytes after the payload")]
    TrailingBytes,
    #[error("fragment conflicts with earlier data for the same handshake")]
    Conflict,
    #[error("too many handshakes in progress")]
    TooManyHandshakes,
    #[error("fragments exceed the declared total length")]
    Overflow,
    #[error("reassembled length does not match the declared total length")]
    LengthMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeFragment {
    pub version: u8,
    pub handshake_id: u64,
    pub suite: u16,
    pub fragment_index: u16,
    pub fragment_count: u16,
    pub total_len: u32,
    pub payload: Vec<u8>,
}

impl HandshakeFragment {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.push(self.version);
        out.extend_from_slice(&self.handshake_id.to_be_bytes());
        out.extend_from_slice(&self.suite.to_be_bytes());
        out.extend_from_slice(&self.fragment_index.to_be_bytes());
        out.extend_from_slice(&self.fragment_count.to_be_bytes());
        out.extend_from_slice(&self.total_len.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Validate every length field against the buffer before allocating.
    pub fn decode(buf: &[u8]) -> Result<Self, FragmentError> {
        if buf.len() < HEADER_LEN {
            return Err(FragmentError::Truncated);
        }
        let version = buf[0];
        if version != FRAGMENT_VERSION {
            return Err(FragmentError::UnsupportedVersion(version));
        }
        let handshake_id = u64::from_be_bytes(buf[1..9].try_into().unwrap());
        let suite = u16::from_be_bytes([buf[9], buf[10]]);
        let fragment_index = u16::from_be_bytes([buf[11], buf[12]]);
        let fragment_count = u16::from_be_bytes([buf[13], buf[14]]);
        let total_len = u32::from_be_bytes(buf[15..19].try_into().unwrap());
        let payload_len = u32::from_be_bytes(buf[19..23].try_into().unwrap()) as usize;

        if fragment_count == 0 {
            return Err(FragmentError::ZeroCount);
        }
        if fragment_count > ABS_MAX_FRAGMENTS {
            return Err(FragmentError::TooManyFragments);
        }
        if fragment_index >= fragment_count {
            return Err(FragmentError::IndexOutOfRange {
                index: fragment_index,
                count: fragment_count,
            });
        }
        if total_len == 0 || total_len > ABS_MAX_TOTAL_LEN {
            return Err(FragmentError::BadTotalLen);
        }
        if payload_len == 0 || payload_len > total_len as usize {
            return Err(FragmentError::BadPayloadLen);
        }
        if fragment_count as u32 > total_len {
            // Every fragment carries at least one byte.
            return Err(FragmentError::BadTotalLen);
        }
        let body = &buf[HEADER_LEN..];
        if body.len() < payload_len {
            return Err(FragmentError::Truncated);
        }
        if body.len() > payload_len {
            return Err(FragmentError::TrailingBytes);
        }
        Ok(Self {
            version,
            handshake_id,
            suite,
            fragment_index,
            fragment_count,
            total_len,
            payload: body.to_vec(),
        })
    }
}

/// Split `data` into fragments of at most `max_payload` bytes.
pub fn fragment(
    handshake_id: u64,
    suite: u16,
    data: &[u8],
    max_payload: usize,
) -> Result<Vec<HandshakeFragment>, FragmentError> {
    if data.is_empty() || data.len() > ABS_MAX_TOTAL_LEN as usize {
        return Err(FragmentError::BadTotalLen);
    }
    if max_payload == 0 {
        return Err(FragmentError::BadPayloadLen);
    }
    let count = data.len().div_ceil(max_payload);
    if count > ABS_MAX_FRAGMENTS as usize {
        return Err(FragmentError::TooManyFragments);
    }
    Ok(data
        .chunks(max_payload)
        .enumerate()
        .map(|(i, c)| HandshakeFragment {
            version: FRAGMENT_VERSION,
            handshake_id,
            suite,
            fragment_index: i as u16,
            fragment_count: count as u16,
            total_len: data.len() as u32,
            payload: c.to_vec(),
        })
        .collect())
}

/// Reassembler limits. Worst-case memory is
/// `max_concurrent * max_total_len` payload bytes plus small bookkeeping.
#[derive(Debug, Clone, Copy)]
pub struct ReassemblyLimits {
    pub max_total_len: u32,
    pub max_fragments: u16,
    pub max_concurrent: usize,
    pub timeout_ms: u64,
}

impl Default for ReassemblyLimits {
    fn default() -> Self {
        Self {
            max_total_len: 64 * 1024,
            max_fragments: 64,
            max_concurrent: 16,
            timeout_ms: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    /// Stored; more fragments needed.
    Pending,
    /// Same fragment seen before; ignored.
    Duplicate,
    /// All fragments present.
    Complete {
        handshake_id: u64,
        suite: u16,
        data: Vec<u8>,
    },
}

struct Entry {
    suite: u16,
    count: u16,
    total_len: u32,
    started_ms: u64,
    received: u16,
    received_bytes: u32,
    slots: Vec<Option<Vec<u8>>>,
}

pub struct Reassembler {
    limits: ReassemblyLimits,
    entries: HashMap<u64, Entry>,
}

impl Reassembler {
    pub fn new(limits: ReassemblyLimits) -> Self {
        Self {
            limits,
            entries: HashMap::new(),
        }
    }

    /// Handshakes currently being assembled.
    pub fn in_progress(&self) -> usize {
        self.entries.len()
    }

    /// Drop handshakes older than the timeout; returns how many.
    pub fn expire(&mut self, now_ms: u64) -> usize {
        let timeout = self.limits.timeout_ms;
        let before = self.entries.len();
        self.entries
            .retain(|_, e| now_ms.saturating_sub(e.started_ms) < timeout);
        before - self.entries.len()
    }

    /// Forget one handshake (e.g. after the caller gives up).
    pub fn discard(&mut self, handshake_id: u64) -> bool {
        self.entries.remove(&handshake_id).is_some()
    }

    pub fn push(
        &mut self,
        frag: HandshakeFragment,
        now_ms: u64,
    ) -> Result<PushOutcome, FragmentError> {
        // Re-check the invariants here as well: a fragment may be built by
        // hand rather than decoded.
        if frag.fragment_count == 0 {
            return Err(FragmentError::ZeroCount);
        }
        if frag.fragment_index >= frag.fragment_count {
            return Err(FragmentError::IndexOutOfRange {
                index: frag.fragment_index,
                count: frag.fragment_count,
            });
        }
        if frag.fragment_count > self.limits.max_fragments.min(ABS_MAX_FRAGMENTS) {
            return Err(FragmentError::TooManyFragments);
        }
        if frag.total_len == 0
            || frag.total_len > self.limits.max_total_len.min(ABS_MAX_TOTAL_LEN)
            || frag.fragment_count as u32 > frag.total_len
        {
            return Err(FragmentError::BadTotalLen);
        }
        if frag.payload.is_empty() || frag.payload.len() > frag.total_len as usize {
            return Err(FragmentError::BadPayloadLen);
        }

        if !self.entries.contains_key(&frag.handshake_id) {
            if self.entries.len() >= self.limits.max_concurrent {
                self.expire(now_ms);
            }
            if self.entries.len() >= self.limits.max_concurrent {
                return Err(FragmentError::TooManyHandshakes);
            }
            self.entries.insert(
                frag.handshake_id,
                Entry {
                    suite: frag.suite,
                    count: frag.fragment_count,
                    total_len: frag.total_len,
                    started_ms: now_ms,
                    received: 0,
                    received_bytes: 0,
                    // Bounded by max_fragments, checked above.
                    slots: vec![None; frag.fragment_count as usize],
                },
            );
        }
        let entry = self.entries.get_mut(&frag.handshake_id).expect("inserted");

        if entry.suite != frag.suite
            || entry.count != frag.fragment_count
            || entry.total_len != frag.total_len
        {
            return Err(FragmentError::Conflict);
        }
        let idx = frag.fragment_index as usize;
        if let Some(existing) = &entry.slots[idx] {
            return if *existing == frag.payload {
                Ok(PushOutcome::Duplicate)
            } else {
                Err(FragmentError::Conflict)
            };
        }
        let new_bytes = entry
            .received_bytes
            .checked_add(frag.payload.len() as u32)
            .filter(|b| *b <= entry.total_len)
            .ok_or(FragmentError::Overflow)?;

        entry.received_bytes = new_bytes;
        entry.received += 1;
        entry.slots[idx] = Some(frag.payload);

        if entry.received < entry.count {
            return Ok(PushOutcome::Pending);
        }
        let done = self.entries.remove(&frag.handshake_id).expect("present");
        if done.received_bytes != done.total_len {
            return Err(FragmentError::LengthMismatch);
        }
        let mut data = Vec::with_capacity(done.total_len as usize);
        for s in done.slots.into_iter().flatten() {
            data.extend_from_slice(&s);
        }
        Ok(PushOutcome::Complete {
            handshake_id: frag.handshake_id,
            suite: done.suite,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::seq::SliceRandom;
    use rand::{Rng, SeedableRng};

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + 3) as u8).collect()
    }

    fn reasm() -> Reassembler {
        Reassembler::new(ReassemblyLimits::default())
    }

    #[test]
    fn frozen_header() {
        let f = HandshakeFragment {
            version: 1,
            handshake_id: 0x0102_0304_0506_0708,
            suite: 0x0009,
            fragment_index: 1,
            fragment_count: 3,
            total_len: 0x0000_0102,
            payload: vec![0xDE, 0xAD],
        };
        assert_eq!(
            hex::encode(f.encode()),
            concat!(
                "01",
                "0102030405060708",
                "0009",
                "0001",
                "0003",
                "00000102",
                "00000002",
                "dead"
            )
        );
        assert_eq!(HEADER_LEN, 23);
        assert_eq!(HandshakeFragment::decode(&f.encode()).unwrap(), f);
    }

    #[test]
    fn round_trip_and_reassemble_in_order() {
        let data = sample(1000);
        let frags = fragment(42, 2, &data, 300).unwrap();
        assert_eq!(frags.len(), 4);
        let mut r = reasm();
        let mut out = None;
        for f in frags {
            let f = HandshakeFragment::decode(&f.encode()).unwrap();
            if let PushOutcome::Complete {
                handshake_id,
                suite,
                data,
            } = r.push(f, 0).unwrap()
            {
                assert_eq!((handshake_id, suite), (42, 2));
                out = Some(data);
            }
        }
        assert_eq!(out.unwrap(), data);
        assert_eq!(r.in_progress(), 0);
    }

    #[test]
    fn single_fragment_message() {
        let data = sample(10);
        let mut frags = fragment(1, 1, &data, 100).unwrap();
        assert_eq!(frags.len(), 1);
        match reasm().push(frags.remove(0), 0).unwrap() {
            PushOutcome::Complete { data: d, .. } => assert_eq!(d, data),
            o => panic!("{o:?}"),
        }
    }

    fn header(count: u16, index: u16, total: u32, plen: u32, body: usize) -> Vec<u8> {
        let mut v = vec![FRAGMENT_VERSION];
        v.extend_from_slice(&7u64.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&index.to_be_bytes());
        v.extend_from_slice(&count.to_be_bytes());
        v.extend_from_slice(&total.to_be_bytes());
        v.extend_from_slice(&plen.to_be_bytes());
        v.resize(v.len() + body, 0xAB);
        v
    }

    #[test]
    fn decode_rejections() {
        use FragmentError::*;
        assert_eq!(HandshakeFragment::decode(&[]), Err(Truncated));
        assert_eq!(
            HandshakeFragment::decode(&header(1, 0, 4, 4, 4)[..HEADER_LEN - 1]),
            Err(Truncated)
        );
        let mut bad_ver = header(1, 0, 4, 4, 4);
        bad_ver[0] = 9;
        assert_eq!(
            HandshakeFragment::decode(&bad_ver),
            Err(UnsupportedVersion(9))
        );
        assert_eq!(
            HandshakeFragment::decode(&header(0, 0, 4, 4, 4)),
            Err(ZeroCount)
        );
        assert_eq!(
            HandshakeFragment::decode(&header(2, 2, 4, 2, 2)),
            Err(IndexOutOfRange { index: 2, count: 2 })
        );
        assert_eq!(
            HandshakeFragment::decode(&header(ABS_MAX_FRAGMENTS + 1, 0, 4096, 4, 4)),
            Err(TooManyFragments)
        );
        assert_eq!(
            HandshakeFragment::decode(&header(1, 0, 0, 0, 0)),
            Err(BadTotalLen)
        );
        assert_eq!(
            HandshakeFragment::decode(&header(1, 0, ABS_MAX_TOTAL_LEN + 1, 4, 4)),
            Err(BadTotalLen)
        );
        // Huge declared payload with a tiny body: rejected, nothing allocated.
        assert_eq!(
            HandshakeFragment::decode(&header(1, 0, ABS_MAX_TOTAL_LEN, u32::MAX, 4)),
            Err(BadPayloadLen)
        );
        assert_eq!(
            HandshakeFragment::decode(&header(1, 0, 100, 50, 10)),
            Err(Truncated)
        );
        assert_eq!(
            HandshakeFragment::decode(&header(1, 0, 100, 5, 10)),
            Err(TrailingBytes)
        );
        assert_eq!(
            HandshakeFragment::decode(&header(1, 0, 100, 0, 0)),
            Err(BadPayloadLen)
        );
        // More fragments than bytes.
        assert_eq!(
            HandshakeFragment::decode(&header(5, 0, 3, 1, 1)),
            Err(BadTotalLen)
        );
    }

    #[test]
    fn every_truncation_of_a_valid_frame_is_rejected() {
        let f = fragment(3, 1, &sample(50), 20).unwrap().remove(0).encode();
        for n in 0..f.len() {
            assert!(HandshakeFragment::decode(&f[..n]).is_err(), "len {n}");
        }
    }

    #[test]
    fn fragment_helper_rejections() {
        assert!(fragment(1, 1, &[], 10).is_err());
        assert!(fragment(1, 1, &[1], 0).is_err());
        assert!(fragment(1, 1, &vec![0; ABS_MAX_FRAGMENTS as usize + 1], 1).is_err());
    }

    #[test]
    fn duplicates_are_idempotent_and_conflicts_rejected() {
        let data = sample(100);
        let frags = fragment(5, 1, &data, 40).unwrap();
        let mut r = reasm();
        assert_eq!(r.push(frags[0].clone(), 0).unwrap(), PushOutcome::Pending);
        assert_eq!(r.push(frags[0].clone(), 1).unwrap(), PushOutcome::Duplicate);

        let mut diff_payload = frags[0].clone();
        diff_payload.payload[0] ^= 1;
        assert_eq!(r.push(diff_payload, 1), Err(FragmentError::Conflict));

        let mut diff_suite = frags[1].clone();
        diff_suite.suite = 9;
        assert_eq!(r.push(diff_suite, 1), Err(FragmentError::Conflict));
        let mut diff_total = frags[1].clone();
        diff_total.total_len += 1;
        assert_eq!(r.push(diff_total, 1), Err(FragmentError::Conflict));
        let mut diff_count = frags[1].clone();
        diff_count.fragment_count += 1;
        assert_eq!(r.push(diff_count, 1), Err(FragmentError::Conflict));

        // The honest rest still completes.
        assert_eq!(r.push(frags[1].clone(), 2).unwrap(), PushOutcome::Pending);
        match r.push(frags[2].clone(), 3).unwrap() {
            PushOutcome::Complete { data: d, .. } => assert_eq!(d, data),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn caps_enforced_before_allocation() {
        let limits = ReassemblyLimits {
            max_total_len: 100,
            max_fragments: 4,
            max_concurrent: 2,
            timeout_ms: 1000,
        };
        let mut r = Reassembler::new(limits);
        let mk = |id, count, total, idx| HandshakeFragment {
            version: 1,
            handshake_id: id,
            suite: 1,
            fragment_index: idx,
            fragment_count: count,
            total_len: total,
            payload: vec![1; 1],
        };
        assert_eq!(
            r.push(mk(1, 5, 100, 0), 0),
            Err(FragmentError::TooManyFragments)
        );
        assert_eq!(r.push(mk(1, 2, 101, 0), 0), Err(FragmentError::BadTotalLen));
        assert_eq!(r.push(mk(1, 0, 10, 0), 0), Err(FragmentError::ZeroCount));
        assert_eq!(
            r.push(mk(1, 2, 10, 2), 0),
            Err(FragmentError::IndexOutOfRange { index: 2, count: 2 })
        );
        assert_eq!(r.in_progress(), 0, "rejections leave no state");

        assert!(r.push(mk(1, 2, 10, 0), 0).is_ok());
        assert!(r.push(mk(2, 2, 10, 0), 0).is_ok());
        assert_eq!(
            r.push(mk(3, 2, 10, 0), 0),
            Err(FragmentError::TooManyHandshakes)
        );
        // After the timeout there is room again.
        assert!(r.push(mk(3, 2, 10, 0), 1000).is_ok());
    }

    #[test]
    fn overflow_and_length_mismatch() {
        let mut r = reasm();
        let mk = |idx, len| HandshakeFragment {
            version: 1,
            handshake_id: 9,
            suite: 1,
            fragment_index: idx,
            fragment_count: 2,
            total_len: 10,
            payload: vec![0; len],
        };
        assert_eq!(r.push(mk(0, 6), 0).unwrap(), PushOutcome::Pending);
        assert_eq!(r.push(mk(1, 6), 0), Err(FragmentError::Overflow));
        // Payload shorter than declared total: completes with a mismatch error
        // and the state is dropped.
        assert_eq!(r.push(mk(1, 2), 0), Err(FragmentError::LengthMismatch));
        assert_eq!(r.in_progress(), 0);
    }

    #[test]
    fn expire_uses_injected_clock() {
        let mut r = reasm();
        let f = fragment(1, 1, &sample(100), 40).unwrap();
        r.push(f[0].clone(), 1000).unwrap();
        assert_eq!(r.expire(1000 + 9_999), 0);
        assert_eq!(r.in_progress(), 1);
        assert_eq!(r.expire(1000 + 10_000), 1);
        assert_eq!(r.in_progress(), 0);
        // A clock that goes backwards never panics or expires early.
        r.push(f[0].clone(), 5000).unwrap();
        assert_eq!(r.expire(1), 0);
        assert!(r.discard(1));
        assert!(!r.discard(1));
    }

    #[test]
    fn random_order_and_duplication_reassemble() {
        for seed in 0..200u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let len = rng.gen_range(1..=5000usize);
            let max_payload = rng.gen_range(1..=700usize);
            let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let frags = match fragment(seed, 2, &data, max_payload) {
                Ok(f) => f,
                Err(FragmentError::TooManyFragments) => continue,
                Err(e) => panic!("{e}"),
            };
            let mut stream: Vec<_> = frags.clone();
            for f in &frags {
                for _ in 0..rng.gen_range(0..3) {
                    stream.push(f.clone());
                }
            }
            stream.shuffle(&mut rng);

            let mut r = Reassembler::new(ReassemblyLimits {
                max_total_len: 8192,
                max_fragments: 1024,
                ..Default::default()
            });
            let mut completed = 0;
            let mut got = None;
            for f in stream {
                let wire = f.encode();
                let f = HandshakeFragment::decode(&wire).unwrap();
                match r.push(f, 0) {
                    Ok(PushOutcome::Complete { data, .. }) => {
                        completed += 1;
                        got = Some(data);
                    }
                    Ok(_) => {}
                    // A duplicate arriving after completion starts a fresh
                    // entry (which later expires); it is never an error here.
                    Err(e) => panic!("seed {seed}: {e}"),
                }
            }
            assert_eq!(got.as_deref(), Some(&data[..]), "seed {seed}");
            assert!(completed >= 1);
            // Leftover entries are only post-completion duplicates; they expire.
            r.expire(1_000_000);
            assert_eq!(r.in_progress(), 0);
        }
    }

    #[test]
    fn random_garbage_never_panics_or_overallocates() {
        let mut rng = StdRng::seed_from_u64(99);
        let mut r = reasm();
        for _ in 0..5000 {
            let n = rng.gen_range(0..80usize);
            let mut buf: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
            if n > 0 && rng.gen_bool(0.7) {
                buf[0] = FRAGMENT_VERSION;
            }
            if let Ok(f) = HandshakeFragment::decode(&buf) {
                let _ = r.push(f, 0);
            }
        }
        assert!(r.in_progress() <= ReassemblyLimits::default().max_concurrent);
    }
}
