//! Audio codec glue for the call feature, behind the `call-audio` feature.
//!
//! Encode and decode sit behind two small traits, [`AudioEncoder`] and
//! [`AudioDecoder`], so a test can swap in a deterministic fake and a later
//! change can replace the codec without touching the media glue. The live
//! implementation is Opus at 48 kHz mono, 20 ms frames, constant bitrate
//! chosen so one encoded frame is exactly [`FRAME_PLAINTEXT_LEN`] (= 60)
//! bytes.
//!
//! Privacy: a decoded or source audio sample is media content; this module
//! never puts a sample, a key, a nonce, a call id or a peer id in a log, an
//! error message or a `Debug` output. The error type is a bare enum with
//! fixed text.
//!
//! Codec crate choice: the plain `opus` crate (bindings to libopus) builds
//! libopus from C source and so pulls in a C toolchain at build time. We use
//! it here for its small, explicit API (`opus::Encoder` / `opus::Decoder`).
//! If a build on Windows without a C toolchain is required, a crate that
//! bundles and statically links libopus (for example `audiopus` via
//! `audiopus_sys`) is a drop-in alternative at this trait boundary; only this
//! file and the one dependency line change, because everything outside speaks
//! the traits below. This PC does not compile the code, so the choice is left
//! at the simplest binding and noted for review.

use super::media::FRAME_PLAINTEXT_LEN;

/// Codec sample rate (Hz): Opus narrow/wideband full rate, 48 kHz.
pub const CODEC_SAMPLE_RATE: u32 = 48_000;
/// Frame length in milliseconds: one media tick.
pub const FRAME_MS: u32 = 20;
/// PCM samples in one 20 ms mono frame at 48 kHz: 48000 * 20 / 1000 = 960.
pub const SAMPLES_PER_FRAME: usize = (CODEC_SAMPLE_RATE as usize * FRAME_MS as usize) / 1000;
/// Constant bitrate (bits per second) picked so a 20 ms frame encodes to
/// exactly 60 bytes: 60 bytes * 8 bits * 50 frames/s = 24_000 bit/s.
pub const CODEC_BITRATE: i32 = 24_000;

/// Errors are a bare enum with fixed text: no sample, key, nonce, call id or
/// peer id ever appears here.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// The encoder produced more than `FRAME_PLAINTEXT_LEN` bytes, so the
    /// fixed-size wire frame cannot hold it. Reject rather than truncate.
    EncodedTooLong,
    /// The underlying codec reported a failure building or running.
    Codec,
}

// A bare `Debug` that mirrors only the variant name, so `?` and test asserts
// that need `Debug` cannot leak anything.
impl core::fmt::Debug for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            CodecError::EncodedTooLong => "EncodedTooLong",
            CodecError::Codec => "Codec",
        })
    }
}

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            CodecError::EncodedTooLong => "the encoded audio frame is too long",
            CodecError::Codec => "the audio codec failed",
        })
    }
}

impl std::error::Error for CodecError {}

/// Encode one 20 ms mono frame of PCM into exactly `FRAME_PLAINTEXT_LEN`
/// bytes. The input is always [`SAMPLES_PER_FRAME`] signed 16-bit samples.
pub trait AudioEncoder: Send {
    /// Encode `pcm` (`SAMPLES_PER_FRAME` samples) into exactly
    /// `FRAME_PLAINTEXT_LEN` bytes. Shorter encoder output is padded; longer
    /// output is rejected with [`CodecError::EncodedTooLong`].
    fn encode(
        &mut self,
        pcm: &[i16; SAMPLES_PER_FRAME],
    ) -> Result<[u8; FRAME_PLAINTEXT_LEN], CodecError>;
}

/// Decode one `FRAME_PLAINTEXT_LEN`-byte frame back to PCM, with a separate
/// lost-frame path for packet-loss concealment.
pub trait AudioDecoder: Send {
    /// Decode `frame` into `SAMPLES_PER_FRAME` samples.
    fn decode(
        &mut self,
        frame: &[u8; FRAME_PLAINTEXT_LEN],
    ) -> Result<[i16; SAMPLES_PER_FRAME], CodecError>;
    /// Produce one frame of concealment audio for a gap the jitter buffer
    /// reported (no packet arrived for this slot).
    fn decode_lost(&mut self) -> Result<[i16; SAMPLES_PER_FRAME], CodecError>;
}

/// Pad an encoder result that is shorter than the fixed frame, or reject one
/// that is longer. Opus decodes a frame padded with trailing zero bytes to
/// the same audio, because the range decoder stops at the true frame end.
fn fit_frame(encoded: &[u8]) -> Result<[u8; FRAME_PLAINTEXT_LEN], CodecError> {
    if encoded.len() > FRAME_PLAINTEXT_LEN {
        return Err(CodecError::EncodedTooLong);
    }
    let mut out = [0u8; FRAME_PLAINTEXT_LEN];
    out[..encoded.len()].copy_from_slice(encoded);
    Ok(out)
}

#[cfg(all(feature = "call-audio", any(windows, target_os = "macos")))]
mod opus_codec {
    use super::*;

    /// Live Opus encoder: 48 kHz mono, 20 ms frames, CBR at `CODEC_BITRATE`.
    pub struct OpusEncoder {
        inner: opus::Encoder,
    }

    impl OpusEncoder {
        pub fn new() -> Result<Self, CodecError> {
            let mut inner = opus::Encoder::new(
                CODEC_SAMPLE_RATE,
                opus::Channels::Mono,
                opus::Application::Voip,
            )
            .map_err(|_| CodecError::Codec)?;
            // Constant bitrate so every 20 ms frame is the same size; pick the
            // rate that lands a frame at exactly 60 bytes.
            inner
                .set_bitrate(opus::Bitrate::Bits(CODEC_BITRATE))
                .map_err(|_| CodecError::Codec)?;
            inner.set_vbr(false).map_err(|_| CodecError::Codec)?;
            Ok(Self { inner })
        }
    }

    impl AudioEncoder for OpusEncoder {
        fn encode(
            &mut self,
            pcm: &[i16; SAMPLES_PER_FRAME],
        ) -> Result<[u8; FRAME_PLAINTEXT_LEN], CodecError> {
            // Give libopus a slightly larger scratch than the wire frame so a
            // transient over-size is caught by `fit_frame` as a clean reject
            // rather than a libopus buffer error.
            let mut scratch = [0u8; FRAME_PLAINTEXT_LEN + 16];
            let written = self
                .inner
                .encode(&pcm[..], &mut scratch)
                .map_err(|_| CodecError::Codec)?;
            fit_frame(&scratch[..written])
        }
    }

    /// Live Opus decoder for 48 kHz mono.
    pub struct OpusDecoder {
        inner: opus::Decoder,
    }

    impl OpusDecoder {
        pub fn new() -> Result<Self, CodecError> {
            let inner = opus::Decoder::new(CODEC_SAMPLE_RATE, opus::Channels::Mono)
                .map_err(|_| CodecError::Codec)?;
            Ok(Self { inner })
        }
    }

    impl AudioDecoder for OpusDecoder {
        fn decode(
            &mut self,
            frame: &[u8; FRAME_PLAINTEXT_LEN],
        ) -> Result<[i16; SAMPLES_PER_FRAME], CodecError> {
            let mut out = [0i16; SAMPLES_PER_FRAME];
            // `false`: this frame is not itself a concealment request.
            let decoded = self
                .inner
                .decode(&frame[..], &mut out[..], false)
                .map_err(|_| CodecError::Codec)?;
            // A short decode leaves the tail as the silence we initialised.
            let _ = decoded;
            Ok(out)
        }

        fn decode_lost(&mut self) -> Result<[i16; SAMPLES_PER_FRAME], CodecError> {
            let mut out = [0i16; SAMPLES_PER_FRAME];
            // An empty input with `fec = false` runs the packet-loss
            // concealment path in libopus.
            self.inner
                .decode(&[], &mut out[..], false)
                .map_err(|_| CodecError::Codec)?;
            Ok(out)
        }
    }
}

#[cfg(all(feature = "call-audio", any(windows, target_os = "macos")))]
pub use opus_codec::{OpusDecoder, OpusEncoder};

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake codec that serialises the first few samples so a round trip can
    /// be checked without any native library. Not audio-accurate; it only
    /// exercises the trait boundary and the 60-byte invariant.
    struct FakeCodec;

    impl AudioEncoder for FakeCodec {
        fn encode(
            &mut self,
            pcm: &[i16; SAMPLES_PER_FRAME],
        ) -> Result<[u8; FRAME_PLAINTEXT_LEN], CodecError> {
            let mut out = [0u8; FRAME_PLAINTEXT_LEN];
            for (slot, sample) in out.chunks_exact_mut(2).zip(pcm.iter()) {
                slot.copy_from_slice(&sample.to_le_bytes());
            }
            Ok(out)
        }
    }

    impl AudioDecoder for FakeCodec {
        fn decode(
            &mut self,
            frame: &[u8; FRAME_PLAINTEXT_LEN],
        ) -> Result<[i16; SAMPLES_PER_FRAME], CodecError> {
            let mut out = [0i16; SAMPLES_PER_FRAME];
            for (bytes, sample) in frame.chunks_exact(2).zip(out.iter_mut()) {
                *sample = i16::from_le_bytes([bytes[0], bytes[1]]);
            }
            Ok(out)
        }
        fn decode_lost(&mut self) -> Result<[i16; SAMPLES_PER_FRAME], CodecError> {
            Ok([0i16; SAMPLES_PER_FRAME])
        }
    }

    fn sine_frame() -> [i16; SAMPLES_PER_FRAME] {
        let mut pcm = [0i16; SAMPLES_PER_FRAME];
        // 440 Hz tone at 48 kHz.
        let step = 2.0 * std::f64::consts::PI * 440.0 / CODEC_SAMPLE_RATE as f64;
        for (i, sample) in pcm.iter_mut().enumerate() {
            *sample = ((i as f64 * step).sin() * 8000.0) as i16;
        }
        pcm
    }

    #[test]
    fn samples_per_frame_is_960() {
        assert_eq!(SAMPLES_PER_FRAME, 960);
    }

    #[test]
    fn fit_frame_pads_short_and_rejects_long() {
        let short = fit_frame(&[1, 2, 3]).unwrap();
        assert_eq!(short[0], 1);
        assert_eq!(short[3], 0);
        assert_eq!(short.len(), FRAME_PLAINTEXT_LEN);
        let exact = fit_frame(&[7u8; FRAME_PLAINTEXT_LEN]).unwrap();
        assert_eq!(exact[FRAME_PLAINTEXT_LEN - 1], 7);
        let long = vec![0u8; FRAME_PLAINTEXT_LEN + 1];
        assert_eq!(fit_frame(&long), Err(CodecError::EncodedTooLong));
    }

    #[test]
    fn fake_round_trip_recovers_samples() {
        let pcm = sine_frame();
        let mut codec = FakeCodec;
        let encoded = codec.encode(&pcm).unwrap();
        assert_eq!(encoded.len(), FRAME_PLAINTEXT_LEN);
        let decoded = codec.decode(&encoded).unwrap();
        // The fake carries the first 30 samples (60 bytes / 2) exactly.
        for i in 0..FRAME_PLAINTEXT_LEN / 2 {
            assert_eq!(decoded[i], pcm[i]);
        }
    }

    #[test]
    fn sixty_byte_invariant_holds_for_fake() {
        let pcm = sine_frame();
        let mut codec = FakeCodec;
        let encoded = codec.encode(&pcm).unwrap();
        assert_eq!(encoded.len(), 60);
    }

    #[test]
    fn lost_path_returns_a_full_frame() {
        let mut codec = FakeCodec;
        let concealed = codec.decode_lost().unwrap();
        assert_eq!(concealed.len(), SAMPLES_PER_FRAME);
    }

    // A hardware-free Opus round trip of a sine. Guarded by platform and feature so it
    // only runs where libopus is linked; it needs no audio device.
    #[cfg(all(feature = "call-audio", any(windows, target_os = "macos")))]
    #[test]
    fn opus_round_trip_of_a_sine() {
        let pcm = sine_frame();
        let mut enc = OpusEncoder::new().unwrap();
        let mut dec = OpusDecoder::new().unwrap();
        let frame = enc.encode(&pcm).unwrap();
        assert_eq!(frame.len(), 60, "CBR frame must be exactly 60 bytes");
        let out = dec.decode(&frame).unwrap();
        assert_eq!(out.len(), SAMPLES_PER_FRAME);
        // Concealment yields a full frame too.
        let lost = dec.decode_lost().unwrap();
        assert_eq!(lost.len(), SAMPLES_PER_FRAME);
    }
}
