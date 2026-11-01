//! Holding a sealed message for a contact who is offline.
//!
//! A custody store with hard limits behind the [`holder::CustodyStore`] trait,
//! and a client that deposits copies at trusted holders and collects what is
//! waiting for it through the [`client::MailboxTransport`] trait. The store is
//! in memory only and is nothing until it is switched on: a node that holds
//! nothing (the default, `chat.custody_enabled = false`) refuses every deposit.
//!
//! The custody verbs travel on the chat channel (ALPN `miasma/chat/1`): [`wire`]
//! is their frame format and [`transport`] the concrete transport that dials a
//! holder and runs one request per stream. The chat service builds the store,
//! answers the verbs for its trusted contacts, deposits a copy when a direct
//! send cannot go through, and collects on reconnect.
//!
//! What is held is the sealed envelope exactly as the sender would put it on
//! the wire, so a holder learns nothing a relay of the connection would not,
//! and the recipient applies it through the same path as a direct delivery
//! (duplicates are dropped by message number). One copy per holder is made;
//! splitting a message into fragments is not part of this step.

pub mod client;
pub mod holder;
pub mod ids;
pub mod transport;
pub mod wire;

#[cfg(test)]
mod sim_tests;
