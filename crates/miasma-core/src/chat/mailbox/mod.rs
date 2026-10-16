//! Holding a sealed message for a contact who is offline.
//!
//! This is the in-memory part only: a custody store with hard limits behind
//! the [`holder::CustodyStore`] trait, and a client that deposits copies at
//! trusted holders and collects what is waiting for it through the
//! [`client::MailboxTransport`] trait. No network protocol uses it yet and
//! nothing here listens for connections; a node that holds nothing (the
//! default, `chat.custody_enabled = false`) refuses every deposit.
//!
//! What is held is the sealed envelope exactly as the sender would put it on
//! the wire, so a holder learns nothing a relay of the connection would not,
//! and the recipient applies it through the same path as a direct delivery
//! (duplicates are dropped by message number). One copy per holder is made;
//! splitting a message into fragments is not part of this step.

pub mod client;
pub mod holder;
pub mod ids;

#[cfg(test)]
mod sim_tests;
