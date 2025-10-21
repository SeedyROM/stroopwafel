use crate::predicate::Predicate;
use crate::{Result, StroopwafelError};
use std::collections::HashMap;

/// A verifier checks whether caveat predicates are satisfied
///
/// Implement this trait to provide custom caveat verification logic.
pub trait Verifier {
    /// Verifies a single caveat predicate
    ///
    /// # Arguments
    /// * `predicate` - The caveat predicate to verify (e.g., "account = alice")
    ///
    /// # Returns
    /// * `Ok(())` if the caveat is satisfied
    /// * `Err(StroopwafelError::CaveatViolation)` if the caveat is violated
    fn verify_caveat(&self, predicate: &[u8]) -> Result<()>;
}

/// A simple verifier that accepts all caveats
///
/// Useful for testing or when you only care about signature verification
pub struct AcceptAllVerifier;

impl Verifier for AcceptAllVerifier {
    fn verify_caveat(&self, _predicate: &[u8]) -> Result<()> {
        Ok(())
    }
}

/// A verifier that rejects all caveats
///
/// Useful for testing failure cases
pub struct RejectAllVerifier;

impl Verifier for RejectAllVerifier {
    fn verify_caveat(&self, predicate: &[u8]) -> Result<()> {
        Err(StroopwafelError::CaveatViolation(
            String::from_utf8_lossy(predicate).to_string(),
        ))
    }
}

/// A function-based verifier for simple use cases
///
/// # Example
/// ```
/// use stroopwafel::verifier::{Verifier, FnVerifier};
///
/// let verifier = FnVerifier::new(|predicate| {
///     if predicate == b"account = alice" {
///         Ok(())
///     } else {
///         Err(stroopwafel::StroopwafelError::CaveatViolation(
///             "Account mismatch".to_string()
///         ))
///     }
/// });
///
/// assert!(verifier.verify_caveat(b"account = alice").is_ok());
/// assert!(verifier.verify_caveat(b"account = bob").is_err());
/// ```
pub struct FnVerifier<F>
where
    F: Fn(&[u8]) -> Result<()>,
{
    func: F,
}

impl<F> FnVerifier<F>
where
    F: Fn(&[u8]) -> Result<()>,
{
    /// Creates a new function-based verifier
    pub fn new(func: F) -> Self {
        Self { func }
    }
}

impl<F> Verifier for FnVerifier<F>
where
    F: Fn(&[u8]) -> Result<()>,
{
    fn verify_caveat(&self, predicate: &[u8]) -> Result<()> {
        (self.func)(predicate)
    }
}

/// A composite verifier that tries multiple verifiers in sequence
///
/// Each caveat must be verified by at least one of the verifiers.
pub struct CompositeVerifier {
    verifiers: Vec<Box<dyn Verifier>>,
}

impl CompositeVerifier {
    /// Creates a new composite verifier
    pub fn new() -> Self {
        Self {
            verifiers: Vec::new(),
        }
    }

    /// Adds a verifier to the composite
    pub fn add_verifier<V: Verifier + 'static>(mut self, verifier: V) -> Self {
        self.verifiers.push(Box::new(verifier));
        self
    }
}

impl Default for CompositeVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier for CompositeVerifier {
    fn verify_caveat(&self, predicate: &[u8]) -> Result<()> {
        if self.verifiers.is_empty() {
            return Ok(());
        }

        // Try each verifier until one succeeds
        for verifier in &self.verifiers {
            if verifier.verify_caveat(predicate).is_ok() {
                return Ok(());
            }
        }

        // All verifiers failed
        Err(StroopwafelError::CaveatViolation(
            String::from_utf8_lossy(predicate).to_string(),
        ))
    }
}

/// A context-based verifier that evaluates predicates against a context map
///
/// This verifier parses caveat predicates (e.g., "account = alice", "time < 2025-12-31")
/// and evaluates them against a provided context.
///
/// # Example
/// ```
/// use stroopwafel::verifier::{Verifier, ContextVerifier};
/// use std::collections::HashMap;
///
/// let mut context = HashMap::new();
/// context.insert("account".to_string(), "alice".to_string());
/// context.insert("action".to_string(), "read".to_string());
///
/// let verifier = ContextVerifier::new(context);
///
/// // This should pass
/// assert!(verifier.verify_caveat(b"account = alice").is_ok());
/// assert!(verifier.verify_caveat(b"action = read").is_ok());
///
/// // This should fail
/// assert!(verifier.verify_caveat(b"account = bob").is_err());
/// ```
pub struct ContextVerifier {
    context: HashMap<String, String>,
}

impl ContextVerifier {
    /// Creates a new context verifier with the given context
    pub fn new(context: HashMap<String, String>) -> Self {
        Self { context }
    }

    /// Creates a new context verifier with an empty context
    pub fn empty() -> Self {
        Self {
            context: HashMap::new(),
        }
    }

    /// Adds a key-value pair to the context
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Sets a key-value pair in the context
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.context.insert(key.into(), value.into());
    }
}

impl Verifier for ContextVerifier {
    fn verify_caveat(&self, predicate_bytes: &[u8]) -> Result<()> {
        let predicate_str = std::str::from_utf8(predicate_bytes)
            .map_err(|e| StroopwafelError::InvalidFormat(e.to_string()))?;

        let predicate = Predicate::parse(predicate_str)?;

        if predicate.evaluate(&self.context) {
            Ok(())
        } else {
            Err(StroopwafelError::CaveatViolation(format!(
                "Predicate '{predicate_str}' failed"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accept_all_verifier() {
        let verifier = AcceptAllVerifier;
        assert!(verifier.verify_caveat(b"anything").is_ok());
        assert!(verifier.verify_caveat(b"").is_ok());
    }

    #[test]
    fn test_reject_all_verifier() {
        let verifier = RejectAllVerifier;
        assert!(verifier.verify_caveat(b"anything").is_err());
    }

    #[test]
    fn test_fn_verifier() {
        let verifier = FnVerifier::new(|predicate| {
            if predicate == b"allowed" {
                Ok(())
            } else {
                Err(StroopwafelError::CaveatViolation("Not allowed".to_string()))
            }
        });

        assert!(verifier.verify_caveat(b"allowed").is_ok());
        assert!(verifier.verify_caveat(b"denied").is_err());
    }

    #[test]
    fn test_composite_verifier_empty() {
        let verifier = CompositeVerifier::new();
        assert!(verifier.verify_caveat(b"anything").is_ok());
    }

    #[test]
    fn test_composite_verifier_single() {
        let verifier = CompositeVerifier::new().add_verifier(AcceptAllVerifier);
        assert!(verifier.verify_caveat(b"anything").is_ok());
    }

    #[test]
    fn test_composite_verifier_multiple() {
        let verifier = CompositeVerifier::new()
            .add_verifier(FnVerifier::new(|p| {
                if p == b"alice" {
                    Ok(())
                } else {
                    Err(StroopwafelError::CaveatViolation("not alice".to_string()))
                }
            }))
            .add_verifier(FnVerifier::new(|p| {
                if p == b"bob" {
                    Ok(())
                } else {
                    Err(StroopwafelError::CaveatViolation("not bob".to_string()))
                }
            }));

        assert!(verifier.verify_caveat(b"alice").is_ok());
        assert!(verifier.verify_caveat(b"bob").is_ok());
        assert!(verifier.verify_caveat(b"charlie").is_err());
    }

    #[test]
    fn test_context_verifier_basic() {
        let mut context = HashMap::new();
        context.insert("account".to_string(), "alice".to_string());

        let verifier = ContextVerifier::new(context);

        assert!(verifier.verify_caveat(b"account = alice").is_ok());
        assert!(verifier.verify_caveat(b"account = bob").is_err());
    }

    #[test]
    fn test_context_verifier_with_builder() {
        let verifier = ContextVerifier::empty()
            .with("account", "alice")
            .with("action", "read");

        assert!(verifier.verify_caveat(b"account = alice").is_ok());
        assert!(verifier.verify_caveat(b"action = read").is_ok());
        assert!(verifier.verify_caveat(b"action = write").is_err());
    }

    #[test]
    fn test_context_verifier_numeric() {
        let verifier = ContextVerifier::empty()
            .with("age", "25")
            .with("count", "100");

        assert!(verifier.verify_caveat(b"age >= 18").is_ok());
        assert!(verifier.verify_caveat(b"age < 30").is_ok());
        assert!(verifier.verify_caveat(b"count > 50").is_ok());
        assert!(verifier.verify_caveat(b"count > 200").is_err());
    }

    #[test]
    fn test_context_verifier_missing_key() {
        let verifier = ContextVerifier::empty().with("account", "alice");

        let result = verifier.verify_caveat(b"role = admin");
        assert!(result.is_err());
    }

    #[test]
    fn test_context_verifier_invalid_predicate() {
        let verifier = ContextVerifier::empty();

        let result = verifier.verify_caveat(b"not a valid predicate");
        assert!(result.is_err());
    }
}
