//! Directed share v2 — pure cryptographic building blocks (no networking).
//!
//! These modules implement the v2 crypto design: the PeerId/sharing-key
//! credential, the prekey offer, the header and transcript, the key schedule,
//! and envelope sealing and opening. The crypto modules are pure functions; the
//! state machine and swarm wiring land in later work packages. None of this is
//! called from the live v1 path.
//!
//! [`behaviour`] holds the `/miasma/directed/2.0.0` codec and behaviour type. It
//! reuses the v1 framing (a 4-byte length prefix and bincode, bounded by
//! [`crate::directed::protocol::DIRECTED_MSG_MAX`]) over the v2 wire types; it is
//! not yet added to the swarm's behaviour list.
//!
//! Each function that draws randomness or reads the clock has a `*_with(rng,
//! now)` form used by tests; the shipping entry points use `OsRng` and the real
//! clock.

pub mod behaviour;
pub mod credential;
pub mod kdf;
pub mod offer;
pub mod seal;
pub mod transcript;
pub mod wire;
