//! Video frame fragmentation into fixed-size media plaintext bodies.
//!
//! Design: design-call-security-v7e.md chapter 4 (the media_type 0x01 video
//! path). A video frame is an encoded bitstream of up to a few kilobytes. The
//! transport only ever carries a fixed 60-byte plaintext body (constant
//! bit-rate, no silence suppression), so a frame is split into 60-byte
//! plaintext fragments, each carried in one 90-byte media packet with
//! media_type 0x01. A short fragment header sits at the front of each 60-byte
//! body; the remaining bytes carry the bitstream, zero-padded in the final
//! fragment so every body is exactly 60 bytes.
//!
//! No codec is chosen in this slice: fragments carry opaque bytes. The header
//! holds only what reassembly needs (which frame, which fragment, how many
//! fragments, and whether this is a keyframe).
//!
//! ## Codec candidates for the next slice
//!
//! This slice does not encode or decode real video; it only moves opaque
//! bitstream bytes. The next slice must pick an encoder/decoder. Candidates
//! considered:
//!
//! - **AV1 (software, e.g. rav1e encode / dav1d decode).** Royalty-free,
//!   BSD/MIT-style licensing, no per-unit fees. Pure-Rust or C with a Rust
//!   wrapper; builds on Windows with the standard toolchain (dav1d needs a
//!   meson/ninja + nasm build, or a prebuilt library). Best compression, but
//!   software encode is CPU-heavy at call frame rates on weaker machines.
//! - **VP8/VP9 (software, libvpx).** Royalty-free, BSD-style licence. Mature
//!   real-time VP8 path (used widely for calls). Windows build needs the
//!   libvpx C library (yasm/nasm); a Rust wrapper crate exists. Lower CPU than
//!   AV1 software encode; weaker compression.
//! - **H.264 (hardware, OS encoders).** Widely hardware-accelerated. On
//!   Windows the Media Foundation H.264 encoder/decoder is available without
//!   shipping a codec, but H.264 carries patent-pool licensing obligations
//!   that an open protocol should avoid depending on by default.
//! - **Hardware AV1 (OS / GPU encoders).** Newer GPUs expose AV1 encode via
//!   Media Foundation on Windows; royalty-free bitstream, low CPU. Not
//!   universally available, so it cannot be the only path.
//!
//! Recommendation: default to a **software, royalty-free codec (VP8 for the
//! first working real-time path, with AV1 as the quality target)** so the
//! protocol depends on no patent-pool licence, and treat **OS hardware
//! encoders (Media Foundation on Windows) as an optional acceleration** probed
//! at run time with a software fallback. Windows builds of the software codecs
//! need a C build chain (nasm/yasm, and meson/ninja for dav1d) or a vendored
//! prebuilt library; that build work belongs to the codec slice, not here.

use super::media::FRAME_PLAINTEXT_LEN;

/// Fragment header length in bytes, placed at the front of each 60-byte media
/// plaintext body: frame_number(2) + fragment_index(2) + fragment_count(2) +
/// flags(1) + encoded_length(2). The length is present on fragment zero.
pub const FRAGMENT_HEADER_LEN: usize = 9;

/// Bitstream bytes carried in one fragment body (the 60-byte plaintext minus
/// the fragment header). The final fragment of a frame is zero-padded up to
/// the full plaintext length so every packet stays the fixed size.
pub const FRAGMENT_PAYLOAD_LEN: usize = FRAME_PLAINTEXT_LEN - FRAGMENT_HEADER_LEN;

/// Keyframe flag bit in the header `flags` byte. A keyframe can be decoded
/// without reference to earlier frames; the receiver asks for one after it
/// drops an incomplete frame.
pub const FLAG_KEYFRAME: u8 = 0x01;

/// The largest fragment_count a frame may declare. A frame is at most a few
/// kilobytes, so this bounds a frame well under 64 KiB while keeping the field
/// a u16. It also caps the work and memory one frame can ask the receiver to
/// hold before the fragment count is trusted.
pub const MAX_FRAGMENTS_PER_FRAME: u16 = 512;

/// A parse/build error for a video fragment. It carries no frame bytes, frame
/// number or any secret, so it is safe to surface and to format.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum VideoFrameError {
    /// A body was not exactly `FRAME_PLAINTEXT_LEN` bytes.
    BadBodyLength,
    /// The header fields were inconsistent (e.g. index >= count, count == 0,
    /// or count above `MAX_FRAGMENTS_PER_FRAME`).
    BadHeader,
    /// The input frame was empty, or larger than the fragment space allows.
    FrameSize,
}

impl core::fmt::Debug for VideoFrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            VideoFrameError::BadBodyLength => "BadBodyLength",
            VideoFrameError::BadHeader => "BadHeader",
            VideoFrameError::FrameSize => "FrameSize",
        })
    }
}

/// The parsed header of one fragment, read from the front of a 60-byte body.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FragmentHeader {
    pub frame_number: u16,
    pub fragment_index: u16,
    pub fragment_count: u16,
    pub keyframe: bool,
    pub encoded_length: u16,
}

impl FragmentHeader {
    fn validate(&self) -> Result<(), VideoFrameError> {
        if self.fragment_count == 0
            || self.fragment_count > MAX_FRAGMENTS_PER_FRAME
            || self.fragment_index >= self.fragment_count
            || (self.fragment_index == 0
                && (self.encoded_length == 0
                    || (self.encoded_length as usize).div_ceil(FRAGMENT_PAYLOAD_LEN)
                        != self.fragment_count as usize))
            || (self.fragment_index != 0 && self.encoded_length != 0)
        {
            return Err(VideoFrameError::BadHeader);
        }
        Ok(())
    }
}

/// Split one encoded video frame into fixed-size 60-byte plaintext bodies,
/// one per fragment, ready to seal and send with media_type 0x01. The final
/// fragment is zero-padded so every body is exactly `FRAME_PLAINTEXT_LEN`.
///
/// `frame_number` wraps naturally at u16; the receiver only compares it for
/// equality within the small reassembly window, so wrap is harmless.
pub fn fragment_frame(
    frame_number: u16,
    keyframe: bool,
    frame: &[u8],
) -> Result<Vec<[u8; FRAME_PLAINTEXT_LEN]>, VideoFrameError> {
    if frame.is_empty() {
        return Err(VideoFrameError::FrameSize);
    }
    let count = frame.len().div_ceil(FRAGMENT_PAYLOAD_LEN);
    if count > MAX_FRAGMENTS_PER_FRAME as usize {
        return Err(VideoFrameError::FrameSize);
    }
    let fragment_count = count as u16;
    let mut bodies = Vec::with_capacity(count);
    for index in 0..count {
        let start = index * FRAGMENT_PAYLOAD_LEN;
        let end = (start + FRAGMENT_PAYLOAD_LEN).min(frame.len());
        let chunk = &frame[start..end];
        let mut body = [0u8; FRAME_PLAINTEXT_LEN];
        let header = FragmentHeader {
            frame_number,
            fragment_index: index as u16,
            fragment_count,
            keyframe,
            encoded_length: if index == 0 { frame.len() as u16 } else { 0 },
        };
        write_header(&mut body, &header);
        body[FRAGMENT_HEADER_LEN..FRAGMENT_HEADER_LEN + chunk.len()].copy_from_slice(chunk);
        bodies.push(body);
    }
    Ok(bodies)
}

/// Write a fragment header into the first `FRAGMENT_HEADER_LEN` bytes of a body.
fn write_header(body: &mut [u8; FRAME_PLAINTEXT_LEN], header: &FragmentHeader) {
    body[0..2].copy_from_slice(&header.frame_number.to_be_bytes());
    body[2..4].copy_from_slice(&header.fragment_index.to_be_bytes());
    body[4..6].copy_from_slice(&header.fragment_count.to_be_bytes());
    body[6] = if header.keyframe { FLAG_KEYFRAME } else { 0 };
    body[7..9].copy_from_slice(&header.encoded_length.to_be_bytes());
}

/// Parse the fragment header and return it together with the fragment's
/// payload slice (still padded to `FRAGMENT_PAYLOAD_LEN`). The caller trims
/// padding using the known total frame length during reassembly.
pub fn parse_fragment(body: &[u8]) -> Result<(FragmentHeader, &[u8]), VideoFrameError> {
    if body.len() != FRAME_PLAINTEXT_LEN {
        return Err(VideoFrameError::BadBodyLength);
    }
    let header = FragmentHeader {
        frame_number: u16::from_be_bytes([body[0], body[1]]),
        fragment_index: u16::from_be_bytes([body[2], body[3]]),
        fragment_count: u16::from_be_bytes([body[4], body[5]]),
        keyframe: body[6] & FLAG_KEYFRAME != 0,
        encoded_length: u16::from_be_bytes([body[7], body[8]]),
    };
    header.validate()?;
    Ok((header, &body[FRAGMENT_HEADER_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Round trip: a frame of many sizes splits into fixed-size bodies and
    // reassembles (in order) to exactly the original bytes.
    #[test]
    fn fragment_reassemble_round_trip_many_sizes() {
        for len in [1usize, 2, 52, 53, 54, 60, 106, 200, 1000, 4096, 8192] {
            let frame: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let bodies = fragment_frame(42, len % 2 == 0, &frame).unwrap();
            let expected_count = len.div_ceil(FRAGMENT_PAYLOAD_LEN);
            assert_eq!(bodies.len(), expected_count);
            let mut out = Vec::new();
            for (i, body) in bodies.iter().enumerate() {
                assert_eq!(body.len(), FRAME_PLAINTEXT_LEN);
                let (h, payload) = parse_fragment(body).unwrap();
                assert_eq!(h.frame_number, 42);
                assert_eq!(h.fragment_index, i as u16);
                assert_eq!(h.fragment_count as usize, expected_count);
                assert_eq!(h.encoded_length as usize, if i == 0 { len } else { 0 });
                out.extend_from_slice(payload);
            }
            out.truncate(len);
            assert_eq!(out, frame);
        }
    }

    #[test]
    fn empty_frame_rejected() {
        assert_eq!(
            fragment_frame(0, true, &[]).unwrap_err(),
            VideoFrameError::FrameSize
        );
    }

    #[test]
    fn oversize_frame_rejected() {
        let too_big = vec![0u8; MAX_FRAGMENTS_PER_FRAME as usize * FRAGMENT_PAYLOAD_LEN + 1];
        assert_eq!(
            fragment_frame(0, true, &too_big).unwrap_err(),
            VideoFrameError::FrameSize
        );
    }

    #[test]
    fn wrong_body_length_rejected() {
        assert_eq!(
            parse_fragment(&[0u8; 59]).unwrap_err(),
            VideoFrameError::BadBodyLength
        );
        assert_eq!(
            parse_fragment(&[0u8; 61]).unwrap_err(),
            VideoFrameError::BadBodyLength
        );
    }

    #[test]
    fn inconsistent_header_rejected() {
        // count == 0
        let mut body = [0u8; FRAME_PLAINTEXT_LEN];
        assert_eq!(
            parse_fragment(&body).unwrap_err(),
            VideoFrameError::BadHeader
        );
        // index >= count
        body[2..4].copy_from_slice(&3u16.to_be_bytes());
        body[4..6].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(
            parse_fragment(&body).unwrap_err(),
            VideoFrameError::BadHeader
        );
        // count above the ceiling
        body[2..4].copy_from_slice(&0u16.to_be_bytes());
        body[4..6].copy_from_slice(&(MAX_FRAGMENTS_PER_FRAME + 1).to_be_bytes());
        assert_eq!(
            parse_fragment(&body).unwrap_err(),
            VideoFrameError::BadHeader
        );
    }

    #[test]
    fn keyframe_flag_preserved() {
        let frame = vec![9u8; 100];
        let key = fragment_frame(7, true, &frame).unwrap();
        for body in &key {
            assert!(parse_fragment(body).unwrap().0.keyframe);
        }
        let delta = fragment_frame(8, false, &frame).unwrap();
        for body in &delta {
            assert!(!parse_fragment(body).unwrap().0.keyframe);
        }
    }
}
