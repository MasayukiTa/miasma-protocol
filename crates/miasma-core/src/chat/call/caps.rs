//! Pure capability encoding and negotiation for call media.

use super::signal;

pub const VERSION: u8 = 1;
pub const MEDIA_AUDIO: u8 = 1 << 0;
pub const MEDIA_VIDEO: u8 = 1 << 1;
pub const MEDIA_SCREEN: u8 = 1 << 2;
/// The first supported audio codec bit; its concrete codec is selected later.
pub const AUDIO_CODEC_DEFAULT: u8 = 1 << 0;
/// The first supported video codec bit; its concrete codec is selected later.
pub const VIDEO_CODEC_DEFAULT: u8 = 1 << 0;

const KNOWN_MEDIA: u8 = MEDIA_AUDIO | MEDIA_VIDEO | MEDIA_SCREEN;
const ENCODED_LEN: usize = 4;
const MAX_TRAILING: usize = 32;

/// Version 1 capability flags. Unknown flags can be received and preserved,
/// but negotiation never selects them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Capabilities {
    pub version: u8,
    pub media_types: u8,
    pub audio_codecs: u8,
    pub video_codecs: u8,
}

impl Capabilities {
    pub fn audio_only() -> Self {
        Self {
            version: VERSION,
            media_types: MEDIA_AUDIO,
            audio_codecs: AUDIO_CODEC_DEFAULT,
            video_codecs: 0,
        }
    }

    pub fn default_local() -> Self {
        Self {
            version: VERSION,
            media_types: KNOWN_MEDIA,
            audio_codecs: AUDIO_CODEC_DEFAULT,
            video_codecs: VIDEO_CODEC_DEFAULT,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        vec![
            self.version,
            self.media_types,
            self.audio_codecs,
            self.video_codecs,
        ]
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CapsError> {
        let version = *bytes.first().ok_or(CapsError::Truncated)?;
        if version != VERSION {
            return Err(CapsError::UnsupportedVersion);
        }
        if bytes.len() < ENCODED_LEN {
            return Err(CapsError::Truncated);
        }
        if bytes.len() > ENCODED_LEN + MAX_TRAILING {
            return Err(CapsError::TrailingBytes);
        }
        Ok(Self {
            version,
            media_types: bytes[1],
            audio_codecs: bytes[2],
            video_codecs: bytes[3],
        })
    }
}

/// The known flags agreed by both peers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Negotiated {
    pub media_types: u8,
    pub audio_codecs: u8,
    pub video_codecs: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CapsError {
    #[error("unsupported capability version")]
    UnsupportedVersion,
    #[error("the capability block was truncated")]
    Truncated,
    #[error("the capability block had too many trailing bytes")]
    TrailingBytes,
    #[error("no common audio media or codec")]
    NoCommonMedia,
}

impl core::fmt::Debug for CapsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::Truncated => "Truncated",
            Self::TrailingBytes => "TrailingBytes",
            Self::NoCommonMedia => "NoCommonMedia",
        })
    }
}

impl CapsError {
    /// Generic refusal: signalling has no compatibility-specific reason code.
    pub fn reason(&self) -> u8 {
        signal::reason::DECLINED
    }
}

/// Intersect supported flags, requiring audio and a common audio codec.
pub fn negotiate(offer: &Capabilities, answer: &Capabilities) -> Result<Negotiated, CapsError> {
    if offer.version != VERSION || answer.version != VERSION {
        return Err(CapsError::UnsupportedVersion);
    }
    let mut media_types = offer.media_types & answer.media_types & KNOWN_MEDIA;
    let audio_codecs = offer.audio_codecs & answer.audio_codecs & AUDIO_CODEC_DEFAULT;
    if media_types & MEDIA_AUDIO == 0 || audio_codecs == 0 {
        return Err(CapsError::NoCommonMedia);
    }
    let mut video_codecs = offer.video_codecs & answer.video_codecs & VIDEO_CODEC_DEFAULT;
    if video_codecs == 0 {
        media_types &= !(MEDIA_VIDEO | MEDIA_SCREEN);
    }
    if media_types & (MEDIA_VIDEO | MEDIA_SCREEN) == 0 {
        video_codecs = 0;
    }
    Ok(Negotiated {
        media_types,
        audio_codecs,
        video_codecs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_size() {
        for caps in [Capabilities::audio_only(), Capabilities::default_local()] {
            let bytes = caps.encode();
            assert!(bytes.len() <= signal::MAX_CAPABILITIES_LEN);
            assert_eq!(Capabilities::decode(&bytes), Ok(caps));
        }
    }

    #[test]
    fn decode_boundaries() {
        for bytes in [&[][..], &[1][..], &[1, 0][..], &[1, 0, 0][..]] {
            assert_eq!(Capabilities::decode(bytes), Err(CapsError::Truncated));
        }
        assert_eq!(
            Capabilities::decode(&[2]),
            Err(CapsError::UnsupportedVersion)
        );
        let mut bytes = Capabilities::default_local().encode();
        bytes.extend_from_slice(&[0; 32]);
        assert_eq!(
            Capabilities::decode(&bytes),
            Ok(Capabilities::default_local())
        );
        bytes.push(0);
        assert_eq!(Capabilities::decode(&bytes), Err(CapsError::TrailingBytes));
    }

    #[test]
    fn intersections_and_unknown_bits() {
        let full = Capabilities::default_local();
        let audio = Capabilities::audio_only();
        assert_eq!(
            negotiate(&audio, &full),
            Ok(Negotiated {
                media_types: MEDIA_AUDIO,
                audio_codecs: AUDIO_CODEC_DEFAULT,
                video_codecs: 0
            })
        );
        let mut unknown = full;
        unknown.media_types |= 0xf8;
        unknown.audio_codecs |= 0xfe;
        unknown.video_codecs |= 0xfe;
        let decoded = Capabilities::decode(&unknown.encode()).unwrap();
        assert_eq!(negotiate(&decoded, &unknown), negotiate(&full, &full));
        let mut mismatch = full;
        mismatch.audio_codecs = 2;
        assert_eq!(negotiate(&full, &mismatch), Err(CapsError::NoCommonMedia));
        mismatch = full;
        mismatch.media_types &= !MEDIA_AUDIO;
        assert_eq!(negotiate(&full, &mismatch), Err(CapsError::NoCommonMedia));
        mismatch = full;
        mismatch.video_codecs = 2;
        assert_eq!(negotiate(&full, &mismatch), negotiate(&full, &audio));
        mismatch.version = 2;
        assert_eq!(
            negotiate(&full, &mismatch),
            Err(CapsError::UnsupportedVersion)
        );
    }

    #[test]
    fn arbitrary_input_does_not_panic() {
        let mut state = 0x12345678u32;
        for i in 0..2000 {
            let mut bytes = vec![0; i % 80];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            let _ = Capabilities::decode(&bytes);
        }
    }
}
