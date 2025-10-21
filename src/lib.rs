pub mod caveat;
pub mod crypto;
pub mod error;
pub mod predicate;
pub mod serialization;
pub mod stroopwafel;
pub mod verifier;

pub use caveat::Caveat;
pub use error::StroopwafelError;
pub use stroopwafel::Stroopwafel;

/// Result type for stroopwafel operations
pub type Result<T> = std::result::Result<T, StroopwafelError>;
