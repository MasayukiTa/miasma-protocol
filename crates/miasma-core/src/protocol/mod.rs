//! Protocol-level building blocks that are independent of any one transport.
//!
//! * [`capability`]: versioned capability sets and degrade-to-common-level
//!   negotiation. A build never refuses to talk to an older or newer build
//!   only because of its version; it settles on the highest level both sides
//!   understand and reports (visibly) when that is below what it wanted.
//! * [`fragment`]: framing and bounded reassembly for handshake messages that
//!   are larger than one transport unit.
//!
//! Both modules are libraries only. Nothing here is wired into a live
//! handshake yet.

pub mod capability;
pub mod fragment;
