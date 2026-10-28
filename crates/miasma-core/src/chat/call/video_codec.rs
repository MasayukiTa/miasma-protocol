//! Baseline JPEG is patent-free, pure Rust, and needs no extra build tools.
//! Each picture is independent, making loss recovery simple and robust. AV1
//! can be revisited when a safe pure Rust decoder API is available.

use jpeg_encoder::{ColorType, Encoder};
use zune_jpeg::zune_core::bytestream::ZCursor;

use super::video::{EncodedVideoFrame, RawPicture, VideoDecoder, VideoEncoder};
use super::video_frame::{FRAGMENT_PAYLOAD_LEN, MAX_FRAGMENTS_PER_FRAME};

pub const VIDEO_WIDTH: u16 = 160;
pub const VIDEO_HEIGHT: u16 = 120;
const WIDTH: usize = VIDEO_WIDTH as usize;
const HEIGHT: usize = VIDEO_HEIGHT as usize;
const LUMA: usize = WIDTH * HEIGHT;
const CHROMA: usize = LUMA / 4;
const FRAME_LIMIT: usize = MAX_FRAGMENTS_PER_FRAME as usize * FRAGMENT_PAYLOAD_LEN;

/// Codec failures contain no media data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VideoCodecError {
    InvalidDimensions,
    InvalidFrame,
    FrameTooLarge,
    Encoder,
    Decoder,
}

/// Encodes full-range eight-bit I420 as independent baseline JPEG pictures.
pub struct JpegEncoder;

impl JpegEncoder {
    pub fn new(width: u16, height: u16) -> Result<Self, VideoCodecError> {
        if (width, height) != (VIDEO_WIDTH, VIDEO_HEIGHT) {
            return Err(VideoCodecError::InvalidDimensions);
        }
        Ok(Self)
    }

    pub fn encode(&mut self, i420: &[u8]) -> Result<EncodedVideoFrame, VideoCodecError> {
        if i420.len() != LUMA + 2 * CHROMA {
            return Err(VideoCodecError::InvalidFrame);
        }
        let mut ycbcr = Vec::with_capacity(LUMA * 3);
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                let c = (y / 2) * (WIDTH / 2) + x / 2;
                ycbcr.extend_from_slice(&[
                    i420[y * WIDTH + x],
                    i420[LUMA + c],
                    i420[LUMA + CHROMA + c],
                ]);
            }
        }
        for quality in [40, 20] {
            let mut data = Vec::new();
            Encoder::new(&mut data, quality)
                .encode(&ycbcr, VIDEO_WIDTH, VIDEO_HEIGHT, ColorType::Ycbcr)
                .map_err(|_| VideoCodecError::Encoder)?;
            if data.len() <= FRAME_LIMIT {
                return Ok(EncodedVideoFrame {
                    keyframe: true,
                    data,
                });
            }
        }
        Err(VideoCodecError::FrameTooLarge)
    }

    /// No action is needed: every JPEG picture is a keyframe.
    pub fn request_keyframe(&mut self) {}
}

impl VideoEncoder for JpegEncoder {
    fn encode(&mut self, picture: &RawPicture) -> Option<EncodedVideoFrame> {
        if (picture.width, picture.height) != (VIDEO_WIDTH, VIDEO_HEIGHT) {
            return None;
        }
        JpegEncoder::encode(self, &picture.pixels).ok()
    }
    fn request_keyframe(&mut self) {
        JpegEncoder::request_keyframe(self);
    }
}

/// Decodes JPEG pictures into full-range eight-bit I420.
pub struct JpegDecoder {
    // The decoder is deliberately stateless across frames.
}

impl JpegDecoder {
    pub fn new(width: u16, height: u16) -> Result<Self, VideoCodecError> {
        if (width, height) != (VIDEO_WIDTH, VIDEO_HEIGHT) {
            return Err(VideoCodecError::InvalidDimensions);
        }
        Ok(Self {})
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<RawPicture, VideoCodecError> {
        if data.len() > FRAME_LIMIT || !data.ends_with(&[0xff, 0xd9]) {
            return Err(VideoCodecError::InvalidFrame);
        }
        // Contain decoder panics on malformed network input when unwinding is enabled.
        std::panic::catch_unwind(|| decode_picture(data)).unwrap_or(Err(VideoCodecError::Decoder))
    }
}

fn decode_picture(data: &[u8]) -> Result<RawPicture, VideoCodecError> {
    let mut decoder = zune_jpeg::JpegDecoder::new(ZCursor::new(data));
    let options = (*decoder.options())
        .set_max_width(WIDTH)
        .set_max_height(HEIGHT)
        .set_strict_mode(true);
    decoder.set_options(options);
    decoder
        .decode_headers()
        .map_err(|_| VideoCodecError::Decoder)?;
    let info = decoder.info().ok_or(VideoCodecError::Decoder)?;
    if (info.width, info.height) != (VIDEO_WIDTH, VIDEO_HEIGHT) {
        return Err(VideoCodecError::InvalidDimensions);
    }
    if decoder.output_buffer_size() != Some(LUMA * 3) {
        return Err(VideoCodecError::InvalidFrame);
    }
    let rgb = decoder.decode().map_err(|_| VideoCodecError::Decoder)?;
    if rgb.len() != LUMA * 3 {
        return Err(VideoCodecError::InvalidFrame);
    }
    let mut pixels = vec![0; LUMA + 2 * CHROMA];
    let mut cb = vec![0i32; CHROMA];
    let mut cr = vec![0i32; CHROMA];
    for y in 0..HEIGHT {
        for x in 0..WIDTH {
            let i = y * WIDTH + x;
            let r = i32::from(rgb[3 * i]);
            let g = i32::from(rgb[3 * i + 1]);
            let b = i32::from(rgb[3 * i + 2]);
            pixels[i] = ((77 * r + 150 * g + 29 * b + 128) >> 8).clamp(0, 255) as u8;
            let c = (y / 2) * (WIDTH / 2) + x / 2;
            cb[c] += ((-43 * r - 85 * g + 128 * b + 128) >> 8) + 128;
            cr[c] += ((128 * r - 107 * g - 21 * b + 128) >> 8) + 128;
        }
    }
    for c in 0..CHROMA {
        pixels[LUMA + c] = ((cb[c] + 2) / 4).clamp(0, 255) as u8;
        pixels[LUMA + CHROMA + c] = ((cr[c] + 2) / 4).clamp(0, 255) as u8;
    }
    Ok(RawPicture {
        width: VIDEO_WIDTH,
        height: VIDEO_HEIGHT,
        pixels,
    })
}

impl VideoDecoder for JpegDecoder {
    fn decode(&mut self, frame: &EncodedVideoFrame) -> Option<RawPicture> {
        JpegDecoder::decode(self, &frame.data).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gradient(t: usize) -> Vec<u8> {
        let mut pixels = vec![128; LUMA + 2 * CHROMA];
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                pixels[y * WIDTH + x] = ((x + y + t * 3) % 256) as u8;
            }
        }
        pixels
    }

    #[test]
    fn moving_gradient_stays_within_transport_frame_limit() {
        let mut encoder = JpegEncoder::new(VIDEO_WIDTH, VIDEO_HEIGHT).unwrap();
        let mut decoder = JpegDecoder::new(VIDEO_WIDTH, VIDEO_HEIGHT).unwrap();
        for t in 0..10 {
            let input = gradient(t);
            let frame = encoder.encode(&input).unwrap();
            assert!(frame.keyframe);
            assert!(frame.data.len() <= FRAME_LIMIT);
            assert!(frame.data.len() < 4096);
            let decoded = decoder.decode(&frame.data).unwrap();
            let mse = input
                .iter()
                .zip(&decoded.pixels)
                .map(|(&a, &b)| {
                    let d = f64::from(a) - f64::from(b);
                    d * d
                })
                .sum::<f64>()
                / input.len() as f64;
            // 25 dB is conservative for this smooth gradient at quality 40.
            assert!(mse < 65025.0 / 10f64.powf(2.5), "MSE: {mse}");
        }
    }

    #[test]
    fn decoder_rejects_arbitrary_input() {
        let mut decoder = JpegDecoder::new(VIDEO_WIDTH, VIDEO_HEIGHT).unwrap();
        assert!(decoder.decode(&[0xff; 32]).is_err());
        let mut encoder = JpegEncoder::new(VIDEO_WIDTH, VIDEO_HEIGHT).unwrap();
        let frame = encoder.encode(&gradient(0)).unwrap();
        for end in [0, 2, frame.data.len() / 2, frame.data.len() - 1] {
            assert!(decoder.decode(&frame.data[..end]).is_err());
        }
    }

    #[test]
    fn wrong_dimensions_are_rejected() {
        let mut data = Vec::new();
        Encoder::new(&mut data, 40)
            .encode(&vec![128; 16 * 16 * 3], 16, 16, ColorType::Rgb)
            .unwrap();
        let mut decoder = JpegDecoder::new(VIDEO_WIDTH, VIDEO_HEIGHT).unwrap();
        assert!(matches!(
            decoder.decode(&data),
            Err(VideoCodecError::InvalidDimensions)
        ));
    }
}
