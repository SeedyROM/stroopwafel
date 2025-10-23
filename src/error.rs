use thiserror::Error;

/// Errors that can occur when working with stroopwafels
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum StroopwafelError {
    /// The stroopwafel's signature is invalid
    #[error("Invalid stroopwafel signature")]
    InvalidSignature,

    /// A caveat condition was violated
    #[error("Caveat violation: {0}")]
    CaveatViolation(String),

    /// Failed to deserialize the stroopwafel
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// The stroopwafel format is invalid
    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Invalid key length
    #[error("Invalid key length")]
    InvalidKeyLength,
}
