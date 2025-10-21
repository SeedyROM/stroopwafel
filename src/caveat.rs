use serde::{Deserialize, Serialize};

/// A caveat represents a restriction on the authorization granted by a macaroon.
/// Caveats can be either first-party (verified by the service) or third-party
/// (verified by an external party).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caveat {
    /// The caveat identifier (the predicate or condition)
    pub caveat_id: Vec<u8>,

    /// Optional verification key identifier (for third-party caveats)
    /// This is the encrypted verification key
    pub verification_key_id: Option<Vec<u8>>,

    /// Optional location of the third-party verifier
    pub location: Option<String>,
}

impl Caveat {
    /// Creates a new first-party caveat
    pub fn first_party(caveat_id: impl Into<Vec<u8>>) -> Self {
        Self {
            caveat_id: caveat_id.into(),
            verification_key_id: None,
            location: None,
        }
    }

    /// Creates a new third-party caveat
    pub fn third_party(
        caveat_id: impl Into<Vec<u8>>,
        verification_key_id: impl Into<Vec<u8>>,
        location: impl Into<String>,
    ) -> Self {
        Self {
            caveat_id: caveat_id.into(),
            verification_key_id: Some(verification_key_id.into()),
            location: Some(location.into()),
        }
    }

    /// Returns true if this is a first-party caveat
    pub fn is_first_party(&self) -> bool {
        self.verification_key_id.is_none() && self.location.is_none()
    }

    /// Returns true if this is a third-party caveat
    pub fn is_third_party(&self) -> bool {
        !self.is_first_party()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_party_caveat() {
        let caveat = Caveat::first_party(b"account = alice");
        assert!(caveat.is_first_party());
        assert!(!caveat.is_third_party());
        assert_eq!(caveat.caveat_id, b"account = alice");
        assert_eq!(caveat.verification_key_id, None);
        assert_eq!(caveat.location, None);
    }

    #[test]
    fn test_third_party_caveat() {
        let caveat = Caveat::third_party(
            b"account = alice",
            b"encrypted_key",
            "https://auth.example.com",
        );
        assert!(caveat.is_third_party());
        assert!(!caveat.is_first_party());
        assert_eq!(caveat.caveat_id, b"account = alice");
        assert_eq!(caveat.verification_key_id, Some(b"encrypted_key".to_vec()));
        assert_eq!(
            caveat.location,
            Some("https://auth.example.com".to_string())
        );
    }
}
