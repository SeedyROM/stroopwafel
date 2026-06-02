use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};

use crate::crypto::hmac_sha3;
use crate::{Result, StroopwafelError};

/// Size of the ChaCha20-Poly1305 nonce in bytes
const NONCE_SIZE: usize = 12;

/// Derives a 32-byte encryption key from an arbitrary-length shared secret.
fn derive_key(shared_key: &[u8]) -> [u8; 32] {
    hmac_sha3(shared_key, b"stroopwafel:encryption:v1")
}

/// Converts a byte slice to a 12-byte array, then into a `Nonce`.
fn nonce_from_slice(bytes: &[u8]) -> Result<Nonce> {
    let arr: [u8; NONCE_SIZE] = bytes.try_into().map_err(|_| {
        StroopwafelError::InvalidFormat(format!(
            "Expected {NONCE_SIZE}-byte nonce, got {} bytes",
            bytes.len()
        ))
    })?;
    Ok(arr.into())
}

/// Encrypts a verification key using a shared secret.
///
/// Use this before passing a verification key to
/// [`Stroopwafel::add_third_party_caveat`](crate::Stroopwafel::add_third_party_caveat).
/// The shared secret must be known to both the issuer and the third-party service.
///
/// The returned bytes encode a random nonce followed by the ciphertext and
/// Poly1305 authentication tag: `nonce (12 bytes) || ciphertext+tag`.
///
/// # Example
/// ```
/// use stroopwafel::{encrypt_verification_key, decrypt_verification_key};
///
/// let shared_secret = b"secret-known-by-issuer-and-third-party";
/// let vk = b"random-verification-key";
///
/// let encrypted = encrypt_verification_key(shared_secret, vk).unwrap();
/// let decrypted = decrypt_verification_key(shared_secret, &encrypted).unwrap();
///
/// assert_eq!(decrypted, vk);
/// ```
pub fn encrypt_verification_key(shared_key: &[u8], verification_key: &[u8]) -> Result<Vec<u8>> {
    let derived = derive_key(shared_key);
    let cipher = ChaCha20Poly1305::new_from_slice(&derived)
        .map_err(|_| StroopwafelError::InvalidKeyLength)?;

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, verification_key)
        .map_err(|_| StroopwafelError::CryptoError("Encryption failed".into()))?;

    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypts a verification key previously encrypted with [`encrypt_verification_key`].
///
/// The third-party service calls this to recover the verification key, which it
/// then uses as the root key when creating a discharge macaroon.
///
/// # Errors
/// Returns [`StroopwafelError::CryptoError`] if the data was tampered with or
/// the wrong shared secret is provided (authentication failure).
pub fn decrypt_verification_key(shared_key: &[u8], encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < NONCE_SIZE {
        return Err(StroopwafelError::InvalidFormat(
            "Encrypted verification key is too short".into(),
        ));
    }

    let derived = derive_key(shared_key);
    let cipher = ChaCha20Poly1305::new_from_slice(&derived)
        .map_err(|_| StroopwafelError::InvalidKeyLength)?;

    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
    let nonce = nonce_from_slice(nonce_bytes)?;

    cipher.decrypt(&nonce, ciphertext).map_err(|_| {
        StroopwafelError::CryptoError("Decryption failed — wrong key or tampered data".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let shared_key = b"shared-secret-key";
        let vk = b"my-verification-key";

        let encrypted = encrypt_verification_key(shared_key, vk).unwrap();
        let decrypted = decrypt_verification_key(shared_key, &encrypted).unwrap();

        assert_eq!(decrypted, vk);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertexts() {
        let shared_key = b"shared-secret-key";
        let vk = b"my-verification-key";

        let enc1 = encrypt_verification_key(shared_key, vk).unwrap();
        let enc2 = encrypt_verification_key(shared_key, vk).unwrap();

        // Random nonces mean two encryptions of the same plaintext differ
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let shared_key = b"correct-key";
        let wrong_key = b"wrong-key";
        let vk = b"verification-key";

        let encrypted = encrypt_verification_key(shared_key, vk).unwrap();
        let result = decrypt_verification_key(wrong_key, &encrypted);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StroopwafelError::CryptoError(_)
        ));
    }

    #[test]
    fn test_decrypt_tampered_data_fails() {
        let shared_key = b"shared-secret-key";
        let vk = b"verification-key";

        let mut encrypted = encrypt_verification_key(shared_key, vk).unwrap();

        // Flip a byte in the ciphertext portion
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xff;

        let result = decrypt_verification_key(shared_key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_too_short_fails() {
        let shared_key = b"key";
        let too_short = [0u8; 5];

        let result = decrypt_verification_key(shared_key, &too_short);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StroopwafelError::InvalidFormat(_)
        ));
    }

    #[test]
    fn test_encrypt_empty_verification_key() {
        let shared_key = b"key";
        let vk = b"";

        let encrypted = encrypt_verification_key(shared_key, vk).unwrap();
        let decrypted = decrypt_verification_key(shared_key, &encrypted).unwrap();

        assert_eq!(decrypted, vk);
    }

    #[test]
    fn test_derive_key_is_deterministic() {
        let key1 = derive_key(b"same-secret");
        let key2 = derive_key(b"same-secret");
        assert_eq!(key1, key2);

        let key3 = derive_key(b"different-secret");
        assert_ne!(key1, key3);
    }
}
