//! Directed private sharing — recipient-bound encrypted file delivery.
//!
//! # Protocol
//!
//! Directed sharing allows a sender to target a specific recipient using
//! public-key-based binding, with a password second factor and a one-time
//! confirmation handshake.
//!
//! ## Security model
//!
//! - **Primary**: Recipient X25519 public key binding (ECDH)
//! - **Second factor**: Password (Argon2id → key derivation)
//! - **Anti-misdirection**: One-time confirmation code (8 alphanumeric chars)
//!
//! ## Flow
//!
//! 1. Sender creates directed envelope:
//!    - Encrypts content with ECDH(ephemeral, recipient_pubkey) + Argon2id(password)
//!    - Dissolves encrypted content → publishes to network
//!    - Creates envelope with encrypted MID reference
//!
//! 2. Sender delivers envelope to recipient via `/miasma/directed/1.0.0`:
//!    - Recipient generates confirmation challenge (XXXX-XXXX)
//!    - Challenge displayed on recipient's screen
//!
//! 3. Sender enters challenge (out-of-band communication):
//!    - Verified by recipient (constant-time, max 3 attempts, 5 min TTL)
//!    - On success: envelope state → Confirmed
//!
//! 4. Recipient retrieves content:
//!    - Enters sender-defined password
//!    - Derives content key (ECDH + Argon2id)
//!    - Retrieves protected content from network
//!    - Decrypts with content key → plaintext
//!
//! ## Deletion semantics (honest)
//!
//! - **Sender revoke**: Invalidates future retrieval, publishes revocation
//!   to recipient. Does NOT guarantee physical deletion from all network
//!   nodes — content shards may persist on peers that cached them.
//!
//! - **Recipient delete**: Removes local envelope and key material.
//!   Cannot revoke network-side shards.
//!
//! - **Expiry**: Automatic based on sender-defined retention period.
//!   Expired envelopes are no longer retrievable, but shards may persist
//!   until garbage collected by holders.
//!
//! - **What "deletion" really means**: Cryptographic deletion — the key
//!   material needed to decrypt the content is discarded. The encrypted
//!   shards may still exist on the network but are computationally
//!   infeasible to decrypt without the keys.

pub mod challenge;
pub mod envelope;
pub mod inbox;
pub mod protocol;

pub use challenge::{
    generate_challenge, verify_challenge, CHALLENGE_MAX_ATTEMPTS, CHALLENGE_TTL_SECS,
};
pub use envelope::{
    create_envelope, decrypt_directed_content, decrypt_envelope_payload, derive_content_key,
    finalize_envelope, format_sharing_contact, format_sharing_key, parse_sharing_contact,
    parse_sharing_key, DirectedEnvelope, EnvelopePayload, EnvelopeState, RetentionPeriod,
};
pub use inbox::{DirectedInbox, EnvelopeSummary};
pub use protocol::{DirectedCodec, DirectedRequest, DirectedResponse};
