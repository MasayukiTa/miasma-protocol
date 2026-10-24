//! Recovery for the sealed root key: the recovery code, the recovery wrap it
//! unlocks, and the exported backup file.
//!
//! A recovery code is 32 random bytes turned into a sequence of words with the
//! same scheme BIP39 uses: 256 entropy bits plus an 8-bit checksum make 264
//! bits, split into 24 groups of 11 bits, each an index into a 2048-word list.
//! The word list itself is passed in ([`WordList`]); this build embeds none.
//! A recovery wrap ([`wrap`]) derives a key from the code and adds, or removes,
//! a second record in `root.sealed`. The backup file ([`backup`]) keeps the key
//! under a passphrase in its own `MSKX` file.

pub mod backup;
pub mod code;
pub mod wrap;

pub use backup::{BackupError, BackupParams};
pub use code::{CodeError, RecoveryCode, WordList, WORD_COUNT};
pub use wrap::{
    add_recovery_wrap, has_recovery_wrap, open_with_code, remove_recovery_wrap, RecoveryError,
};
