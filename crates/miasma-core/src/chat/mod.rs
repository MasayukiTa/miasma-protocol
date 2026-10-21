//! One-to-one chat between registered contacts (ALPN `miasma/chat/1`).
//!
//! Who may talk to us is decided by the contact list of the trusted-contact
//! push (`allow_receive` for incoming messages, `allow_send` for outgoing
//! ones); the identity of the peer is the endpoint ID proven by the transport
//! handshake. Messages are end-to-end encrypted ([`crypto`]), kept in
//! encrypted state files ([`store`], [`outbox`]) and delivered over a direct
//! connection when both sides are online; otherwise they wait in the outbox
//! and are retried ([`service`]).

pub mod crypto;
pub mod engine;
pub mod group;
pub mod ipc;
pub mod mailbox;
pub mod outbox;
#[cfg(feature = "pqc")]
pub mod pq;
pub mod proto;
pub mod store;
pub mod sync;

#[cfg(feature = "iroh")]
pub mod service;

pub use ipc::{handle_ipc, ChatRequest, ChatResponse};

#[cfg(test)]
mod engine_tests;
#[cfg(test)]
pub(crate) mod offline_tests;
#[cfg(all(test, feature = "pqc"))]
mod pq_tests;
#[cfg(test)]
mod receipt_tests;
#[cfg(test)]
mod restore_tests;
