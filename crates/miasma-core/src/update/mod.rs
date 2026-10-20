//! Self-update: look for a newer build on GitHub Releases (or in a developer's
//! build folder), verify it, swap it in with a way back, and repair an update
//! that was interrupted.
//!
//! The rules the code keeps:
//!
//! * `update.mode = off` means no connection and no program is started: the
//!   check returns before doing anything.
//! * One automatic check per start, not in the first minute ([`schedule`]). A
//!   check that cannot finish is a *failed* check, never "up to date".
//! * A release without `SHA256SUMS.txt` is refused; when public keys are
//!   pinned in the binary a valid Ed25519 signature over it is required too
//!   ([`verify`]).
//! * `update.mode = auto` installs by itself only when the build pins at least
//!   one public key ([`engine::auto_install_allowed`]). Without a key no
//!   signature can be checked, so `auto` behaves like `notify`: the person has
//!   to ask for the install.
//! * The progress file is not trusted: it must name the install folder this
//!   program itself would detect, or it is refused ([`apply`]).
//! * The archive is read as hostile ([`archive`]); the swap is a sequence of
//!   renames with a journal and an automatic way back ([`apply`]).
//! * Nothing is applied while a transfer, push or chat send is running
//!   ([`activity`]).
//! * Log lines go through `tracing` (the in-memory ring buffer in stealth mode)
//!   and never name paths or addresses.

pub mod activity;
pub mod apply;
pub mod archive;
pub mod config;
pub mod engine;
pub mod error;
pub mod http;
pub mod package;
pub mod release;
pub mod schedule;
pub mod state;
pub mod verify;
pub mod version;

pub use config::{UpdateChannel, UpdateConfig, UpdateMode};
pub use engine::{CheckFailure, CheckOutcome, Engine, Source, UpdateOffer};
pub use error::UpdateError;
