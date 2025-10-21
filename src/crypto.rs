use hmac::{Hmac, Mac};
use sha3::Sha3_256;

type HmacSha3 = Hmac<Sha3_256>;

/// Size of HMAC-SHA3-256 output in bytes (32 bytes = 256 bits)
pub const SIGNATURE_SIZE: usize = 32;

/// Generates an HMAC-SHA3-256 signature
///
/// # Arguments
/// * `key` - The secret key
/// * `message` - The message to authenticate
///
/// # Returns
/// A 32-byte HMAC signature
pub fn hmac_sha3(key: &[u8], message: &[u8]) -> [u8; SIGNATURE_SIZE] {
    let mut mac = HmacSha3::new_from_slice(key)
        .expect("HMAC can take key of any length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Binds a new caveat to the signature chain
///
/// This computes: HMAC-SHA3(previous_signature, caveat_id)
///
/// # Arguments
/// * `signature` - The previous signature (used as the key)
/// * `caveat_id` - The caveat identifier to bind
///
/// # Returns
/// A new 32-byte signature
pub fn bind_caveat(signature: &[u8], caveat_id: &[u8]) -> [u8; SIGNATURE_SIZE] {
    hmac_sha3(signature, caveat_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha3_deterministic() {
        let key = b"secret key";
        let message = b"hello world";

        let sig1 = hmac_sha3(key, message);
        let sig2 = hmac_sha3(key, message);

        assert_eq!(sig1, sig2);
        assert_eq!(sig1.len(), SIGNATURE_SIZE);
    }

    #[test]
    fn test_hmac_sha3_different_keys() {
        let message = b"hello world";

        let sig1 = hmac_sha3(b"key1", message);
        let sig2 = hmac_sha3(b"key2", message);

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_hmac_sha3_different_messages() {
        let key = b"secret key";

        let sig1 = hmac_sha3(key, b"message1");
        let sig2 = hmac_sha3(key, b"message2");

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_bind_caveat_chaining() {
        let root_key = b"root secret";
        let identifier = b"my macaroon";

        // Initial signature
        let sig1 = hmac_sha3(root_key, identifier);

        // Add first caveat
        let caveat1 = b"account = alice";
        let sig2 = bind_caveat(&sig1, caveat1);

        // Add second caveat
        let caveat2 = b"action = read";
        let sig3 = bind_caveat(&sig2, caveat2);

        // Each signature should be different
        assert_ne!(sig1, sig2);
        assert_ne!(sig2, sig3);
        assert_ne!(sig1, sig3);

        // Verify we can reconstruct the chain
        let reconstructed_sig2 = bind_caveat(&sig1, caveat1);
        let reconstructed_sig3 = bind_caveat(&reconstructed_sig2, caveat2);

        assert_eq!(sig2, reconstructed_sig2);
        assert_eq!(sig3, reconstructed_sig3);
    }
}
