//! Call feature media-crypto library (PR1).
//!
//! Pure library code: per-call, per-direction media key derivation (MK_root and
//! the one-way chain), frame AEAD, a replay window and the epoch rules. No
//! transport, no signalling, no UI. See design-call-security-v7e.md chapters 2
//! and 4.
//!
//! Everything here keeps the privacy discipline of the chat crypto: secret
//! buffers live in `Zeroizing`, and no key, nonce, call id, peer id or media
//! sample ever reaches a log, an error message or a `Debug` output.

pub mod caps;
pub mod controller;
pub mod device;
pub mod frame;
pub mod inbound;
pub mod jitter;
pub mod media;
#[cfg(feature = "iroh")]
pub mod media_task;
pub mod packet;
pub mod receiver;
#[cfg(feature = "iroh")]
pub mod runtime;
pub mod sas;
pub mod sender;
pub mod session;
pub mod signal;
pub mod state;
pub mod video;
#[cfg(all(feature = "call-video", any(windows, target_os = "macos")))]
pub mod video_codec;
pub mod video_frame;

pub use caps::{negotiate, Capabilities, CapsError, Negotiated};
pub use frame::{open_frame, seal_frame, AdvanceReason, ReplayWindow, SendChain};
pub use inbound::CallInbound;
pub use media::{
    chain_step, derive_mk_root, init_chain_key, media_aad, media_nonce, Direction, MediaError,
    AAD_LEN, EPOCH_MAX_PACKETS, EPOCH_RETAIN, FRAME_PLAINTEXT_LEN, FRAME_WIRE_LEN, KEY_EPOCH_MAX,
    MAX_EPOCH_JUMP, MEDIA_PROTOCOL_VERSION, MEDIA_REKEY_SECONDS, MEDIA_REPLAY_WINDOW, NONCE_LEN,
    TAG_LEN, WIRE_HEADER_LEN,
};
pub use signal::{
    new_call_id, new_call_nonce, offer_hash, reason, Kind, Record, SignalError, CALL_ID_LEN,
    CALL_NONCE_LEN, CALL_TTL_SECONDS_DEFAULT, CALL_TTL_SECONDS_MAX, CALL_TTL_SECONDS_MIN,
    OFFER_HASH_LEN,
};
pub use video::{
    EncodedVideoFrame, PassthroughCodec, RawPicture, Reassembled, ReassemblyBuffer,
    RecordingVideoSink, SendScheduler, TestPatternSource, TickFill, VideoDecoder, VideoEncoder,
    VideoSink, VideoSource, DEFAULT_REASSEMBLY_BUDGET_BYTES, MAX_VIDEO_FRAGMENTS_PER_TICK,
};
pub use video_frame::{
    fragment_frame, parse_fragment, FragmentHeader, VideoFrameError, FLAG_KEYFRAME,
    FRAGMENT_HEADER_LEN, FRAGMENT_PAYLOAD_LEN, MAX_FRAGMENTS_PER_FRAME,
};

#[cfg(all(feature = "call-camera", any(windows, target_os = "macos")))]
pub mod video_camera;
