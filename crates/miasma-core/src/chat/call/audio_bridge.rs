//! Bridges the real audio devices and the Opus codec onto the byte-frame
//! ports the media session speaks ([`AudioSource`] and [`AudioSink`], 60-byte
//! frames). Behind the `call-audio` feature.
//!
//! Send path: capture mono codec-rate PCM, encode one 20 ms frame to exactly
//! `FRAME_PLAINTEXT_LEN` bytes, hand it to the session.
//! Receive path: take a 60-byte frame, decode it to PCM, play it; on a gap the
//! jitter buffer reports, run the decoder's lost-frame path instead.
//!
//! Receive-only operation: with no usable input device the source yields
//! `None` every tick (the session sends no audio) while the output still
//! plays; with no usable output device the sink drops decoded audio. Either
//! way the call proceeds.
//!
//! Privacy: audio samples are media content and never reach a log, an error
//! message or a `Debug` output. None of the types here derive `Debug`.

use super::audio_device::{AudioDeviceError, CpalAudioInput, CpalAudioOutput, DeviceChoice};
use super::codec::{AudioDecoder, AudioEncoder, OpusDecoder, OpusEncoder, SAMPLES_PER_FRAME};
use super::device::{AudioSink, AudioSource};
use super::media::FRAME_PLAINTEXT_LEN;

/// Names chosen for the input and output device, or the host default.
#[derive(Clone, Default)]
pub struct DeviceSelection {
    pub input: DeviceChoice,
    pub output: DeviceChoice,
}

/// A real-device capture source that encodes to 60-byte frames. If the input
/// device is absent it still exists but yields `None` (silence) so the call
/// runs receive-only.
pub struct EncodingSource {
    input: Option<CpalAudioInput>,
    encoder: OpusEncoder,
}

impl EncodingSource {
    /// Build the source. A missing input device is not fatal: the returned
    /// source yields no frames. A codec failure is fatal and returned typed.
    pub fn new(choice: &DeviceChoice) -> Result<Self, AudioDeviceError> {
        let encoder = OpusEncoder::new().map_err(|_| AudioDeviceError::Backend)?;
        let input = match CpalAudioInput::new(choice) {
            Ok(input) => Some(input),
            // Treat an absent or refused device as receive-only, not an error.
            Err(AudioDeviceError::NoDevice)
            | Err(AudioDeviceError::PermissionDenied)
            | Err(AudioDeviceError::Unsupported) => None,
            Err(other) => return Err(other),
        };
        Ok(Self { input, encoder })
    }

    /// Whether a real input device is driving this source.
    pub fn has_input(&self) -> bool {
        self.input.is_some()
    }

    /// Mute the microphone. With no input device this is a no-op.
    pub fn set_muted(&self, muted: bool) {
        if let Some(input) = &self.input {
            input.set_muted(muted);
        }
    }
}

impl AudioSource for EncodingSource {
    fn next_frame(&mut self) -> Option<[u8; FRAME_PLAINTEXT_LEN]> {
        let pcm = self.input.as_mut()?.next_frame()?;
        // A failed encode drops this frame rather than ending the call; the
        // next tick tries again.
        self.encoder.encode(&pcm).ok()
    }
}

/// A real-device playback sink that decodes 60-byte frames. If the output
/// device is absent decoded audio is dropped, so the call runs send-only or
/// fully receive-only without failing.
pub struct DecodingSink {
    output: Option<CpalAudioOutput>,
    decoder: OpusDecoder,
}

impl DecodingSink {
    pub fn new(choice: &DeviceChoice) -> Result<Self, AudioDeviceError> {
        let decoder = OpusDecoder::new().map_err(|_| AudioDeviceError::Backend)?;
        let output = match CpalAudioOutput::new(choice) {
            Ok(output) => Some(output),
            Err(AudioDeviceError::NoDevice)
            | Err(AudioDeviceError::PermissionDenied)
            | Err(AudioDeviceError::Unsupported) => None,
            Err(other) => return Err(other),
        };
        Ok(Self { output, decoder })
    }

    pub fn has_output(&self) -> bool {
        self.output.is_some()
    }

    fn write(&mut self, pcm: &[i16; SAMPLES_PER_FRAME]) {
        if let Some(output) = &mut self.output {
            output.play_frame(pcm);
        }
    }
}

impl AudioSink for DecodingSink {
    fn play(&mut self, frame: &[u8; FRAME_PLAINTEXT_LEN]) {
        if let Ok(pcm) = self.decoder.decode(frame) {
            self.write(&pcm);
        }
    }
    fn conceal(&mut self) {
        // Packet-loss concealment: synthesise one frame for the gap.
        if let Ok(pcm) = self.decoder.decode_lost() {
            self.write(&pcm);
        }
    }
}

/// Build a real capture source and playback sink for a call. A fatal error
/// (codec build, or a backend fault that is not a plain missing device) is
/// returned typed so the controller can post a call notice; a plain missing or
/// refused device is absorbed into receive-only operation inside the source
/// and sink.
pub fn build_real_audio(
    selection: &DeviceSelection,
) -> Result<(EncodingSource, DecodingSink), AudioDeviceError> {
    let source = EncodingSource::new(&selection.input)?;
    let sink = DecodingSink::new(&selection.output)?;
    Ok((source, sink))
}

#[cfg(test)]
mod send_tests {
    use super::*;

    #[test]
    fn media_audio_types_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<CpalAudioInput>();
        assert_send::<CpalAudioOutput>();
        assert_send::<OpusEncoder>();
        assert_send::<OpusDecoder>();
        assert_send::<EncodingSource>();
        assert_send::<DecodingSink>();
        assert_send::<Result<(EncodingSource, DecodingSink), AudioDeviceError>>();
        assert_send::<super::super::controller::MediaRoots>();
        assert_send::<super::super::media_task::MediaStats>();
        assert_send::<
            super::super::session::MediaSession<
                EncodingSource,
                DecodingSink,
                Box<dyn super::super::session::DatagramLink>,
            >,
        >();
    }
}
