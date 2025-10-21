use crate::caveat::Caveat;
use crate::crypto::{SIGNATURE_SIZE, bind_caveat, hmac_sha3};
use crate::verifier::Verifier;
use crate::{Result, StroopwafelError};
use serde::{Deserialize, Serialize};

/// A stroopwafel is a bearer token with embedded, attenuating caveats.
///
/// Stroopwafels use chained HMAC-SHA3-256 signatures to allow for decentralized
/// authorization and delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stroopwafel {
    /// Optional location hint for the target service
    pub location: Option<String>,

    /// Public identifier for this stroopwafel
    pub identifier: Vec<u8>,

    /// List of caveats (restrictions) attached to this stroopwafel
    pub caveats: Vec<Caveat>,

    /// HMAC-SHA3-256 signature (32 bytes)
    pub signature: [u8; SIGNATURE_SIZE],
}

impl Stroopwafel {
    /// Creates a new stroopwafel (minting operation)
    ///
    /// # Arguments
    /// * `root_key` - The secret root key known only to the issuer
    /// * `identifier` - A public identifier for this stroopwafel
    /// * `location` - Optional location hint for the target service
    ///
    /// # Returns
    /// A new stroopwafel with the initial signature
    ///
    /// # Example
    /// ```
    /// use stroopwafel::Stroopwafel;
    ///
    /// let root_key = b"this is our super secret key; only we should know it";
    /// let stroopwafel = Stroopwafel::new(root_key, b"we used our secret key", Some("http://mybank/"));
    /// ```
    pub fn new(
        root_key: &[u8],
        identifier: impl Into<Vec<u8>>,
        location: Option<impl Into<String>>,
    ) -> Self {
        let identifier = identifier.into();
        let signature = hmac_sha3(root_key, &identifier);

        Self {
            location: location.map(|l| l.into()),
            identifier,
            caveats: Vec::new(),
            signature,
        }
    }

    /// Adds a first-party caveat to this stroopwafel
    ///
    /// First-party caveats are restrictions verified by the service itself.
    /// Each caveat is bound to the signature chain using HMAC-SHA3.
    ///
    /// # Arguments
    /// * `predicate` - The caveat condition (e.g., "account = alice", "action = read")
    ///
    /// # Example
    /// ```
    /// use stroopwafel::Stroopwafel;
    ///
    /// let root_key = b"secret";
    /// let mut stroopwafel = Stroopwafel::new(root_key, b"identifier", Some("http://example.com/"));
    /// stroopwafel.add_first_party_caveat(b"account = alice");
    /// stroopwafel.add_first_party_caveat(b"time < 2025-12-31T23:59:59Z");
    /// ```
    pub fn add_first_party_caveat(&mut self, predicate: impl Into<Vec<u8>>) {
        let caveat_id = predicate.into();

        // Bind the caveat to the signature chain
        self.signature = bind_caveat(&self.signature, &caveat_id);

        // Add the caveat to the list
        self.caveats.push(Caveat::first_party(caveat_id));
    }

    /// Adds a third-party caveat to this stroopwafel
    ///
    /// Third-party caveats require verification by an external party.
    ///
    /// # Arguments
    /// * `caveat_id` - The caveat identifier
    /// * `verification_key` - The encrypted verification key for the third party
    /// * `location` - The location of the third-party verifier
    ///
    /// # Example
    /// ```
    /// use stroopwafel::Stroopwafel;
    ///
    /// let root_key = b"secret";
    /// let mut stroopwafel = Stroopwafel::new(root_key, b"identifier", Some("http://example.com/"));
    /// stroopwafel.add_third_party_caveat(
    ///     b"account = alice",
    ///     b"encrypted_verification_key",
    ///     "https://auth.example.com"
    /// );
    /// ```
    pub fn add_third_party_caveat(
        &mut self,
        caveat_id: impl Into<Vec<u8>>,
        verification_key_id: impl Into<Vec<u8>>,
        location: impl Into<String>,
    ) {
        let caveat_id = caveat_id.into();
        let verification_key_id = verification_key_id.into();

        // Bind the caveat to the signature chain
        // For third-party caveats, we bind the verification key ID
        self.signature = bind_caveat(&self.signature, &verification_key_id);

        // Add the caveat to the list
        self.caveats.push(Caveat::third_party(
            caveat_id,
            verification_key_id,
            location,
        ));
    }

    /// Returns the number of caveats in this stroopwafel
    pub fn caveat_count(&self) -> usize {
        self.caveats.len()
    }

    /// Returns true if this stroopwafel has no caveats
    pub fn is_unrestricted(&self) -> bool {
        self.caveats.is_empty()
    }

    /// Creates a discharge macaroon for a third-party caveat
    ///
    /// Discharge macaroons are created by the third party to prove that
    /// a third-party caveat has been satisfied.
    ///
    /// # Arguments
    /// * `verification_key` - The key shared between the issuer and third party
    /// * `caveat_id` - The identifier of the caveat being discharged
    /// * `location` - Optional location of the third-party service
    ///
    /// # Example
    /// ```
    /// use stroopwafel::Stroopwafel;
    ///
    /// // Third party creates a discharge macaroon
    /// let verification_key = b"shared_secret_key";
    /// let discharge = Stroopwafel::create_discharge(
    ///     verification_key,
    ///     b"caveat_identifier",
    ///     Some("https://auth.example.com")
    /// );
    /// ```
    pub fn create_discharge(
        verification_key: &[u8],
        caveat_id: impl Into<Vec<u8>>,
        location: Option<impl Into<String>>,
    ) -> Self {
        Self::new(verification_key, caveat_id, location)
    }

    /// Binds a discharge macaroon to this stroopwafel's signature
    ///
    /// This creates a cryptographic binding between the primary stroopwafel
    /// and a discharge macaroon, preventing them from being used separately.
    ///
    /// # Arguments
    /// * `discharge` - The discharge macaroon to bind
    ///
    /// # Returns
    /// A new discharge macaroon with an updated signature bound to this stroopwafel
    pub fn bind_discharge(&self, discharge: &Stroopwafel) -> Stroopwafel {
        let mut bound_discharge = discharge.clone();

        // Bind: new_sig = HMAC(discharge.signature, primary.signature)
        bound_discharge.signature = hmac_sha3(&discharge.signature, &self.signature);

        bound_discharge
    }

    /// Prepares this stroopwafel for a request by binding all discharge macaroons
    ///
    /// This method takes discharge macaroons and binds them to the primary stroopwafel,
    /// returning a vector containing the primary stroopwafel followed by all bound discharges.
    ///
    /// # Arguments
    /// * `discharges` - Discharge macaroons for third-party caveats
    ///
    /// # Returns
    /// A vector with the primary stroopwafel first, followed by bound discharge macaroons
    ///
    /// # Example
    /// ```
    /// use stroopwafel::Stroopwafel;
    ///
    /// let root_key = b"secret";
    /// let mut primary = Stroopwafel::new(root_key, b"primary", None::<String>);
    /// primary.add_third_party_caveat(
    ///     b"auth_required",
    ///     b"verification_key",
    ///     "https://auth.example.com"
    /// );
    ///
    /// // Third party creates discharge
    /// let discharge = Stroopwafel::create_discharge(
    ///     b"verification_key",
    ///     b"auth_required",
    ///     Some("https://auth.example.com")
    /// );
    ///
    /// // Prepare for request
    /// let stroopwafels = primary.prepare_for_request(vec![discharge]);
    /// assert_eq!(stroopwafels.len(), 2); // Primary + 1 discharge
    /// ```
    pub fn prepare_for_request(&self, discharges: Vec<Stroopwafel>) -> Vec<Stroopwafel> {
        let mut result = vec![self.clone()];

        for discharge in discharges {
            result.push(self.bind_discharge(&discharge));
        }

        result
    }

    /// Verifies this stroopwafel against the root key and verifier
    ///
    /// This performs signature and caveat verification, including support for
    /// third-party caveats with discharge macaroons.
    ///
    /// # Arguments
    /// * `root_key` - The secret root key used to mint this stroopwafel
    /// * `verifier` - A verifier that checks caveat predicates
    /// * `discharges` - Optional discharge macaroons for third-party caveats
    ///
    /// # Returns
    /// * `Ok(())` if the stroopwafel is valid and all caveats are satisfied
    /// * `Err(StroopwafelError)` if signature is invalid or any caveat is violated
    ///
    /// # Example
    /// ```
    /// use stroopwafel::{Stroopwafel, verifier::AcceptAllVerifier};
    ///
    /// let root_key = b"secret";
    /// let mut stroopwafel = Stroopwafel::new(root_key, b"identifier", None::<String>);
    /// stroopwafel.add_first_party_caveat(b"account = alice");
    ///
    /// // Verify with a permissive verifier
    /// let verifier = AcceptAllVerifier;
    /// assert!(stroopwafel.verify(root_key, &verifier, &[]).is_ok());
    /// ```
    pub fn verify(
        &self,
        root_key: &[u8],
        verifier: &impl Verifier,
        discharges: &[Stroopwafel],
    ) -> Result<()> {
        // Step 1: Rebuild the signature chain
        let mut computed_signature = hmac_sha3(root_key, &self.identifier);

        for caveat in &self.caveats {
            if caveat.is_first_party() {
                // For first-party caveats, bind the caveat_id
                computed_signature = bind_caveat(&computed_signature, &caveat.caveat_id);
            } else {
                // For third-party caveats, bind the verification_key_id
                if let Some(ref vk_id) = caveat.verification_key_id {
                    computed_signature = bind_caveat(&computed_signature, vk_id);
                }
            }
        }

        // Step 2: Verify the signature matches
        if computed_signature != self.signature {
            return Err(StroopwafelError::InvalidSignature);
        }

        // Step 3: Verify each caveat
        for caveat in &self.caveats {
            if caveat.is_first_party() {
                // Verify first-party caveat with the verifier
                verifier.verify_caveat(&caveat.caveat_id)?;
            } else {
                // Verify third-party caveat with discharge macaroon
                self.verify_third_party_caveat(caveat, discharges, verifier)?;
            }
        }

        Ok(())
    }

    /// Verifies a third-party caveat using discharge macaroons
    fn verify_third_party_caveat(
        &self,
        caveat: &Caveat,
        discharges: &[Stroopwafel],
        verifier: &impl Verifier,
    ) -> Result<()> {
        // Find the discharge macaroon for this caveat
        let discharge = discharges
            .iter()
            .find(|d| d.identifier == caveat.caveat_id)
            .ok_or_else(|| {
                StroopwafelError::CaveatViolation(format!(
                    "Missing discharge macaroon for caveat: {}",
                    String::from_utf8_lossy(&caveat.caveat_id)
                ))
            })?;

        // Verify the discharge macaroon's binding
        // The discharge signature should be: HMAC(original_discharge_sig, primary.signature)
        // We need to verify the discharge was properly bound
        let verification_key = caveat.verification_key_id.as_ref().ok_or_else(|| {
            StroopwafelError::InvalidFormat(
                "Third-party caveat missing verification key".to_string(),
            )
        })?;

        // Verify the discharge macaroon itself
        discharge.verify_discharge(verification_key, &self.signature, verifier)?;

        Ok(())
    }

    /// Verifies a discharge macaroon
    fn verify_discharge(
        &self,
        verification_key: &[u8],
        primary_signature: &[u8],
        verifier: &impl Verifier,
    ) -> Result<()> {
        // Step 1: Rebuild the discharge's signature chain
        let mut computed_signature = hmac_sha3(verification_key, &self.identifier);

        for caveat in &self.caveats {
            if caveat.is_first_party() {
                computed_signature = bind_caveat(&computed_signature, &caveat.caveat_id);
            } else if let Some(ref vk_id) = caveat.verification_key_id {
                computed_signature = bind_caveat(&computed_signature, vk_id);
            }
        }

        // Step 2: Bind with primary signature
        let expected_signature = hmac_sha3(&computed_signature, primary_signature);

        // Step 3: Verify the bound signature matches
        if expected_signature != self.signature {
            return Err(StroopwafelError::InvalidSignature);
        }

        // Step 4: Verify all first-party caveats in the discharge
        for caveat in &self.caveats {
            if caveat.is_first_party() {
                verifier.verify_caveat(&caveat.caveat_id)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::{AcceptAllVerifier, ContextVerifier, FnVerifier, RejectAllVerifier};

    #[test]
    fn test_new_stroopwafel() {
        let root_key = b"this is our super secret key; only we should know it";
        let identifier = b"we used our secret key";
        let location = "http://mybank/";

        let stroopwafel = Stroopwafel::new(root_key, identifier, Some(location));

        assert_eq!(stroopwafel.identifier, identifier);
        assert_eq!(stroopwafel.location, Some(location.to_string()));
        assert_eq!(stroopwafel.caveats.len(), 0);
        assert_eq!(stroopwafel.signature.len(), SIGNATURE_SIZE);

        // Verify the signature is deterministic
        let stroopwafel2 = Stroopwafel::new(root_key, identifier, Some(location));
        assert_eq!(stroopwafel.signature, stroopwafel2.signature);
    }

    #[test]
    fn test_new_stroopwafel_without_location() {
        let root_key = b"secret";
        let identifier = b"identifier";

        let stroopwafel = Stroopwafel::new(root_key, identifier, None::<String>);

        assert_eq!(stroopwafel.location, None);
        assert_eq!(stroopwafel.identifier, identifier);
    }

    #[test]
    fn test_add_first_party_caveat() {
        let root_key = b"secret";
        let mut stroopwafel =
            Stroopwafel::new(root_key, b"identifier", Some("http://example.com/"));

        let original_signature = stroopwafel.signature;

        stroopwafel.add_first_party_caveat(b"account = alice");

        assert_eq!(stroopwafel.caveats.len(), 1);
        assert_eq!(stroopwafel.caveats[0].caveat_id, b"account = alice");
        assert!(stroopwafel.caveats[0].is_first_party());

        // Signature should have changed
        assert_ne!(stroopwafel.signature, original_signature);
    }

    #[test]
    fn test_add_multiple_first_party_caveats() {
        let root_key = b"secret";
        let mut stroopwafel =
            Stroopwafel::new(root_key, b"identifier", Some("http://example.com/"));

        stroopwafel.add_first_party_caveat(b"account = alice");
        let sig_after_first = stroopwafel.signature;

        stroopwafel.add_first_party_caveat(b"action = read");
        let sig_after_second = stroopwafel.signature;

        assert_eq!(stroopwafel.caveats.len(), 2);
        assert_ne!(sig_after_first, sig_after_second);
    }

    #[test]
    fn test_signature_chaining() {
        let root_key = b"secret";
        let identifier = b"identifier";

        // Create two stroopwafels and add caveats in the same order
        let mut s1 = Stroopwafel::new(root_key, identifier, None::<String>);
        let mut s2 = Stroopwafel::new(root_key, identifier, None::<String>);

        s1.add_first_party_caveat(b"caveat1");
        s2.add_first_party_caveat(b"caveat1");
        assert_eq!(s1.signature, s2.signature);

        s1.add_first_party_caveat(b"caveat2");
        s2.add_first_party_caveat(b"caveat2");
        assert_eq!(s1.signature, s2.signature);
    }

    #[test]
    fn test_add_third_party_caveat() {
        let root_key = b"secret";
        let mut stroopwafel =
            Stroopwafel::new(root_key, b"identifier", Some("http://example.com/"));

        stroopwafel.add_third_party_caveat(
            b"account = alice",
            b"verification_key_123",
            "https://auth.example.com",
        );

        assert_eq!(stroopwafel.caveats.len(), 1);
        assert!(stroopwafel.caveats[0].is_third_party());
        assert_eq!(stroopwafel.caveats[0].caveat_id, b"account = alice");
        assert_eq!(
            stroopwafel.caveats[0].verification_key_id,
            Some(b"verification_key_123".to_vec())
        );
        assert_eq!(
            stroopwafel.caveats[0].location,
            Some("https://auth.example.com".to_string())
        );
    }

    #[test]
    fn test_caveat_count() {
        let root_key = b"secret";
        let mut stroopwafel = Stroopwafel::new(root_key, b"identifier", None::<String>);

        assert_eq!(stroopwafel.caveat_count(), 0);
        assert!(stroopwafel.is_unrestricted());

        stroopwafel.add_first_party_caveat(b"caveat1");
        assert_eq!(stroopwafel.caveat_count(), 1);
        assert!(!stroopwafel.is_unrestricted());

        stroopwafel.add_first_party_caveat(b"caveat2");
        assert_eq!(stroopwafel.caveat_count(), 2);
    }

    #[test]
    fn test_verify_valid_stroopwafel_no_caveats() {
        let root_key = b"secret";
        let stroopwafel = Stroopwafel::new(root_key, b"identifier", None::<String>);

        let verifier = AcceptAllVerifier;
        assert!(stroopwafel.verify(root_key, &verifier, &[]).is_ok());
    }

    #[test]
    fn test_verify_valid_stroopwafel_with_caveats() {
        let root_key = b"secret";
        let mut stroopwafel = Stroopwafel::new(root_key, b"identifier", None::<String>);
        stroopwafel.add_first_party_caveat(b"account = alice");
        stroopwafel.add_first_party_caveat(b"action = read");

        let verifier = AcceptAllVerifier;
        assert!(stroopwafel.verify(root_key, &verifier, &[]).is_ok());
    }

    #[test]
    fn test_verify_wrong_root_key() {
        let root_key = b"secret";
        let stroopwafel = Stroopwafel::new(root_key, b"identifier", None::<String>);

        let wrong_key = b"wrong_secret";
        let verifier = AcceptAllVerifier;
        let result = stroopwafel.verify(wrong_key, &verifier, &[]);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StroopwafelError::InvalidSignature
        ));
    }

    #[test]
    fn test_verify_tampered_signature() {
        let root_key = b"secret";
        let mut stroopwafel = Stroopwafel::new(root_key, b"identifier", None::<String>);
        stroopwafel.add_first_party_caveat(b"account = alice");

        // Tamper with the signature
        stroopwafel.signature[0] ^= 0xff;

        let verifier = AcceptAllVerifier;
        let result = stroopwafel.verify(root_key, &verifier, &[]);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StroopwafelError::InvalidSignature
        ));
    }

    #[test]
    fn test_verify_caveat_violation() {
        let root_key = b"secret";
        let mut stroopwafel = Stroopwafel::new(root_key, b"identifier", None::<String>);
        stroopwafel.add_first_party_caveat(b"account = alice");

        let verifier = RejectAllVerifier;
        let result = stroopwafel.verify(root_key, &verifier, &[]);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StroopwafelError::CaveatViolation(_)
        ));
    }

    #[test]
    fn test_verify_with_custom_verifier() {
        let root_key = b"secret";
        let mut stroopwafel = Stroopwafel::new(root_key, b"identifier", None::<String>);
        stroopwafel.add_first_party_caveat(b"account = alice");
        stroopwafel.add_first_party_caveat(b"action = read");

        // Only allow specific caveats
        let verifier = FnVerifier::new(|predicate| {
            if predicate == b"account = alice" || predicate == b"action = read" {
                Ok(())
            } else {
                Err(StroopwafelError::CaveatViolation(
                    "Unauthorized caveat".to_string(),
                ))
            }
        });

        assert!(stroopwafel.verify(root_key, &verifier, &[]).is_ok());
    }

    #[test]
    fn test_verify_fails_on_specific_caveat() {
        let root_key = b"secret";
        let mut stroopwafel = Stroopwafel::new(root_key, b"identifier", None::<String>);
        stroopwafel.add_first_party_caveat(b"account = alice");
        stroopwafel.add_first_party_caveat(b"action = write"); // This will fail

        let verifier = FnVerifier::new(|predicate| {
            if predicate == b"account = alice" || predicate == b"action = read" {
                Ok(())
            } else {
                Err(StroopwafelError::CaveatViolation(format!(
                    "Caveat not allowed: {}",
                    String::from_utf8_lossy(predicate)
                )))
            }
        });

        let result = stroopwafel.verify(root_key, &verifier, &[]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StroopwafelError::CaveatViolation(_)
        ));
    }

    #[test]
    fn test_verify_with_third_party_caveat() {
        let root_key = b"secret";
        let mut stroopwafel = Stroopwafel::new(root_key, b"identifier", None::<String>);
        stroopwafel.add_first_party_caveat(b"account = alice");
        stroopwafel.add_third_party_caveat(
            b"external_auth",
            b"encrypted_key",
            "https://auth.example.com",
        );

        // Third-party caveats require discharge macaroons
        let verifier = AcceptAllVerifier;

        // Should fail without discharge
        let result = stroopwafel.verify(root_key, &verifier, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_discharge() {
        let verification_key = b"shared_secret";
        let caveat_id = b"auth_required";

        let discharge = Stroopwafel::create_discharge(
            verification_key,
            caveat_id,
            Some("https://auth.example.com"),
        );

        assert_eq!(discharge.identifier, caveat_id);
        assert_eq!(
            discharge.location,
            Some("https://auth.example.com".to_string())
        );
        assert_eq!(discharge.caveats.len(), 0);
    }

    #[test]
    fn test_bind_discharge() {
        let root_key = b"root_secret";
        let primary = Stroopwafel::new(root_key, b"primary", None::<String>);

        let verification_key = b"verification_secret";
        let discharge =
            Stroopwafel::create_discharge(verification_key, b"caveat_id", None::<String>);

        let original_discharge_sig = discharge.signature;
        let bound_discharge = primary.bind_discharge(&discharge);

        // Signature should be different after binding
        assert_ne!(bound_discharge.signature, original_discharge_sig);

        // But other fields should be the same
        assert_eq!(bound_discharge.identifier, discharge.identifier);
        assert_eq!(bound_discharge.caveats, discharge.caveats);
    }

    #[test]
    fn test_prepare_for_request() {
        let root_key = b"secret";
        let mut primary = Stroopwafel::new(root_key, b"primary", None::<String>);

        primary.add_third_party_caveat(
            b"auth_required",
            b"verification_key",
            "https://auth.example.com",
        );

        let discharge =
            Stroopwafel::create_discharge(b"verification_key", b"auth_required", None::<String>);

        let stroopwafels = primary.prepare_for_request(vec![discharge]);

        assert_eq!(stroopwafels.len(), 2); // Primary + 1 discharge
        assert_eq!(stroopwafels[0].identifier, b"primary");
        assert_eq!(stroopwafels[1].identifier, b"auth_required");
    }

    #[test]
    fn test_verify_with_discharge_macaroon() {
        let root_key = b"root_secret";
        let verification_key = b"verification_secret";

        // Create primary stroopwafel with third-party caveat
        let mut primary = Stroopwafel::new(root_key, b"primary_id", None::<String>);
        primary.add_third_party_caveat(b"auth_check", verification_key, "https://auth.example.com");

        // Create discharge macaroon
        let discharge = Stroopwafel::create_discharge(
            verification_key,
            b"auth_check",
            Some("https://auth.example.com"),
        );

        // Bind the discharge
        let bound_discharge = primary.bind_discharge(&discharge);

        // Verify should succeed with the discharge
        let verifier = AcceptAllVerifier;
        assert!(
            primary
                .verify(root_key, &verifier, &[bound_discharge])
                .is_ok()
        );
    }

    #[test]
    fn test_verify_fails_without_discharge() {
        let root_key = b"root_secret";
        let verification_key = b"verification_secret";

        // Create primary stroopwafel with third-party caveat
        let mut primary = Stroopwafel::new(root_key, b"primary_id", None::<String>);
        primary.add_third_party_caveat(b"auth_check", verification_key, "https://auth.example.com");

        // Verify should fail without discharge
        let verifier = AcceptAllVerifier;
        let result = primary.verify(root_key, &verifier, &[]);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StroopwafelError::CaveatViolation(_)
        ));
    }

    #[test]
    fn test_verify_fails_with_wrong_discharge() {
        let root_key = b"root_secret";
        let verification_key = b"verification_secret";

        // Create primary stroopwafel with third-party caveat
        let mut primary = Stroopwafel::new(root_key, b"primary_id", None::<String>);
        primary.add_third_party_caveat(b"auth_check", verification_key, "https://auth.example.com");

        // Create discharge for DIFFERENT caveat
        let wrong_discharge =
            Stroopwafel::create_discharge(verification_key, b"wrong_caveat_id", None::<String>);

        let bound_discharge = primary.bind_discharge(&wrong_discharge);

        // Verify should fail with wrong discharge
        let verifier = AcceptAllVerifier;
        let result = primary.verify(root_key, &verifier, &[bound_discharge]);

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_with_discharge_containing_caveats() {
        let root_key = b"root_secret";
        let verification_key = b"verification_secret";

        // Create primary stroopwafel with third-party caveat
        let mut primary = Stroopwafel::new(root_key, b"primary_id", None::<String>);
        primary.add_first_party_caveat(b"account = alice");
        primary.add_third_party_caveat(b"auth_check", verification_key, "https://auth.example.com");

        // Create discharge macaroon with its own caveats
        let mut discharge =
            Stroopwafel::create_discharge(verification_key, b"auth_check", None::<String>);
        discharge.add_first_party_caveat(b"time < 2025-12-31");

        // Bind the discharge
        let bound_discharge = primary.bind_discharge(&discharge);

        // Create verifier that checks both caveats
        let verifier = ContextVerifier::empty()
            .with("account", "alice")
            .with("time", "2025-01-01");

        // Should succeed
        assert!(
            primary
                .verify(root_key, &verifier, &[bound_discharge])
                .is_ok()
        );
    }

    #[test]
    fn test_verify_discharge_caveat_violation() {
        let root_key = b"root_secret";
        let verification_key = b"verification_secret";

        // Create primary stroopwafel with third-party caveat
        let mut primary = Stroopwafel::new(root_key, b"primary_id", None::<String>);
        primary.add_third_party_caveat(b"auth_check", verification_key, "https://auth.example.com");

        // Create discharge macaroon with a caveat
        let mut discharge =
            Stroopwafel::create_discharge(verification_key, b"auth_check", None::<String>);
        discharge.add_first_party_caveat(b"level >= 10");

        // Bind the discharge
        let bound_discharge = primary.bind_discharge(&discharge);

        // Verifier with wrong level
        let verifier = ContextVerifier::empty().with("level", "5");

        // Should fail due to caveat violation in discharge
        let result = primary.verify(root_key, &verifier, &[bound_discharge]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StroopwafelError::CaveatViolation(_)
        ));
    }

    #[test]
    fn test_multiple_third_party_caveats() {
        let root_key = b"root_secret";
        let vk1 = b"verification_key_1";
        let vk2 = b"verification_key_2";

        // Create primary with multiple third-party caveats
        let mut primary = Stroopwafel::new(root_key, b"primary_id", None::<String>);
        primary.add_third_party_caveat(b"auth1", vk1, "https://auth1.example.com");
        primary.add_third_party_caveat(b"auth2", vk2, "https://auth2.example.com");

        // Create discharge macaroons
        let discharge1 = Stroopwafel::create_discharge(vk1, b"auth1", None::<String>);
        let discharge2 = Stroopwafel::create_discharge(vk2, b"auth2", None::<String>);

        // Bind discharges
        let bound1 = primary.bind_discharge(&discharge1);
        let bound2 = primary.bind_discharge(&discharge2);

        // Should succeed with both discharges
        let verifier = AcceptAllVerifier;
        assert!(
            primary
                .verify(root_key, &verifier, &[bound1, bound2])
                .is_ok()
        );
    }
}
