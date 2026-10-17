//! Trusted-contact push: register the other person once (both sides
//! register each other), then send file after file with no per-file Share ID,
//! password or confirmation code. The receiver auto-accepts only from
//! registered contacts. Transport is the iroh direct endpoint (ALPN
//! `miasma/push/1`); identity is the endpoint ID proven by the handshake.

pub mod contact;
pub mod disk;
pub mod ipc;
pub mod outbox;
pub mod proto;
pub mod retry;
pub mod state;
pub mod store;

#[cfg(feature = "iroh")]
pub mod link;
#[cfg(feature = "iroh")]
pub mod service;

pub use contact::{
    extract_contact_code, fingerprint, fingerprint_matches, ContactCode, ContactCodeError,
    CONTACT_PREFIX,
};
pub use ipc::{handle_ipc, ContactInfo, PushRequest, PushResponse};
pub use state::{Direction, HistoryEntry, PushState, PushTransferInfo};
pub use store::{Contact, ContactError, ContactStore, ContactUpdate};
