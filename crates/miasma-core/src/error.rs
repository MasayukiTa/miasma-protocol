use thiserror::Error;

#[derive(Debug, Error)]
pub enum MiasmaError {
    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed: {0}")]
    Decryption(String),

    #[error("SSS operation failed: {0}")]
    Sss(String),

    #[error("Reed-Solomon encode/decode failed: {0}")]
    ReedSolomon(String),

    #[error("share integrity check failed")]
    ShareIntegrity,

    #[error("invalid MID: {0}")]
    InvalidMid(String),

    #[error("insufficient shares: need {need}, got {got}")]
    InsufficientShares { need: usize, got: usize },

    #[error("hash mismatch: content does not match MID")]
    HashMismatch,

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("serialization failed: {0}")]
    Serialization(String),

    #[error("DHT error: {0}")]
    Dht(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("storage error: {0}")]
    Storage(String),
}
