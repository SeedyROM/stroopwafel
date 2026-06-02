use std::collections::HashSet;

/// Checks whether a stroopwafel identifier has been revoked.
///
/// Implement this trait to plug in your own revocation store (database, Redis, etc.).
/// Pass an implementation to [`Stroopwafel::verify_checked`](crate::Stroopwafel::verify_checked).
pub trait RevocationChecker {
    /// Returns `true` if the given identifier has been revoked.
    fn is_revoked(&self, identifier: &[u8]) -> bool;
}

/// An in-memory set of revoked stroopwafel identifiers.
///
/// Suitable for testing or small deployments. For production use, back this with
/// a persistent store and implement [`RevocationChecker`] directly.
///
/// # Example
/// ```
/// use stroopwafel::{RevocationChecker, RevocationList};
/// use stroopwafel::{Stroopwafel, verifier::AcceptAllVerifier};
///
/// let root_key = b"secret";
/// let mut token = Stroopwafel::new(root_key, b"session-abc", None::<String>);
///
/// let mut revoked = RevocationList::new();
/// revoked.revoke(b"session-abc");
///
/// // verify_checked rejects revoked identifiers before checking signatures
/// let result = token.verify_checked(root_key, &AcceptAllVerifier, &[], &revoked);
/// assert!(result.is_err());
/// ```
#[derive(Debug, Default, Clone)]
pub struct RevocationList {
    revoked: HashSet<Vec<u8>>,
}

impl RevocationList {
    /// Creates an empty revocation list.
    pub fn new() -> Self {
        Self {
            revoked: HashSet::new(),
        }
    }

    /// Marks an identifier as revoked. Returns `true` if it was not already revoked.
    pub fn revoke(&mut self, identifier: impl Into<Vec<u8>>) -> bool {
        self.revoked.insert(identifier.into())
    }

    /// Removes a previously revoked identifier. Returns `true` if it was revoked.
    pub fn unrevoke(&mut self, identifier: &[u8]) -> bool {
        self.revoked.remove(identifier)
    }

    /// Returns the number of revoked identifiers.
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// Returns `true` if no identifiers have been revoked.
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
}

impl RevocationChecker for RevocationList {
    fn is_revoked(&self, identifier: &[u8]) -> bool {
        self.revoked.contains(identifier)
    }
}

/// A [`RevocationChecker`] that never revokes anything.
///
/// Useful as a no-op placeholder when revocation is not needed.
pub struct NoRevocation;

impl RevocationChecker for NoRevocation {
    fn is_revoked(&self, _identifier: &[u8]) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revoke_and_check() {
        let mut list = RevocationList::new();
        assert!(!list.is_revoked(b"abc"));

        list.revoke(b"abc");
        assert!(list.is_revoked(b"abc"));
        assert!(!list.is_revoked(b"def"));
    }

    #[test]
    fn test_unrevoke() {
        let mut list = RevocationList::new();
        list.revoke(b"abc");
        assert!(list.is_revoked(b"abc"));

        let removed = list.unrevoke(b"abc");
        assert!(removed);
        assert!(!list.is_revoked(b"abc"));
    }

    #[test]
    fn test_revoke_returns_false_on_duplicate() {
        let mut list = RevocationList::new();
        assert!(list.revoke(b"abc"));
        assert!(!list.revoke(b"abc")); // already revoked
    }

    #[test]
    fn test_len_and_is_empty() {
        let mut list = RevocationList::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);

        list.revoke(b"a");
        list.revoke(b"b");
        assert_eq!(list.len(), 2);
        assert!(!list.is_empty());
    }

    #[test]
    fn test_no_revocation_never_revokes() {
        let checker = NoRevocation;
        assert!(!checker.is_revoked(b"anything"));
        assert!(!checker.is_revoked(b""));
    }
}
