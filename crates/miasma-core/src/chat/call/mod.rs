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

pub mod frame;
pub mod media;
pub mod state;

pub use frame::{open_frame, seal_frame, AdvanceReason, ReplayWindow, SendChain};
pub use media::{
    chain_step, derive_mk_root, init_chain_key, media_aad, media_nonce, Direction, MediaError,
    AAD_LEN, EPOCH_MAX_PACKETS, EPOCH_RETAIN, FRAME_PLAINTEXT_LEN, FRAME_WIRE_LEN, KEY_EPOCH_MAX,
    MAX_EPOCH_JUMP, MEDIA_PROTOCOL_VERSION, MEDIA_REKEY_SECONDS, MEDIA_REPLAY_WINDOW, NONCE_LEN,
    TAG_LEN, WIRE_HEADER_LEN,
};
