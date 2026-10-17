//! Group chat: small groups of people who message each other pairwise.
//!
//! * [`membership`]: the signed member list (descriptors, epochs, the chain
//!   that makes a forged change detectable);
//! * [`record`]: what travels inside the sealed pairwise envelopes;
//! * [`state`], [`store`]: what is kept per group, in the encrypted chat store;
//! * [`engine`]: the engine (create, add, remove, leave, send, receive);
//! * [`ipc`]: the request surface used by the CLI;
//! * `service`: the network side (own ALPN, one delivery worker per member).
//!
//! Group traffic uses its own connection (ALPN `miasma/chat-group/1`), not the
//! one of the private chat. The private chat's receiver closes a connection
//! on a frame type it does not know (`serve` leaves its loop at the first
//! frame that does not parse), so a group frame sent over that connection to a
//! peer that predates groups would end the private conversation's connection
//! too. A peer without groups does not list the group ALPN at all: the dial
//! fails for the group connection only, and nothing else is affected.

pub mod engine;
pub mod ipc;
pub mod membership;
pub mod record;
pub mod state;
pub mod store;

#[cfg(test)]
mod engine_tests;

#[cfg(feature = "iroh")]
pub mod service;

pub use self::engine::{GroupCore, GroupError};
pub use ipc::{GroupRequest, GroupResponse};
