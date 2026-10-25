//! Directed share v2 — pure cryptographic building blocks (no networking).
//!
//! These modules implement the v2 crypto design: the PeerId/sharing-key
//! credential, the prekey offer, the header and transcript, the key schedule,
//! and envelope sealing and opening. Everything here is a pure function; the
//! networking, state machine and wiring land in later work packages. None of
//! this is called from the live v1 path.
//!
//! Each function that draws randomness or reads the clock has a `*_with(rng,
//! now)` form used by tests; the shipping entry points use `OsRng` and the real
//! clock.

pub mod credential;
pub mod invite_intake;
pub mod kdf;
pub mod offer;
pub mod seal;
pub mod transcript;
pub mod wire;
