#![doc = include_str!("../README.md")]
#![allow(rustdoc::broken_intra_doc_links)]

pub mod caveat;
pub mod crypto;
pub mod encryption;
pub mod error;
pub mod predicate;
pub mod revocation;
pub mod serialization;
pub mod stroopwafel;
pub mod verifier;

pub use caveat::Caveat;
pub use error::StroopwafelError;
pub use revocation::{NoRevocation, RevocationChecker, RevocationList};
pub use stroopwafel::Stroopwafel;

/// Result type for stroopwafel operations
pub type Result<T> = std::result::Result<T, StroopwafelError>;
