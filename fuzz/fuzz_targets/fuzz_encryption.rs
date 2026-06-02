#![no_main]

use libfuzzer_sys::fuzz_target;
use stroopwafel::{decrypt_verification_key, encrypt_verification_key};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // Use the first byte as a split point so key and plaintext vary independently
    let split = (data[0] as usize).min(data.len() - 1);
    let shared_key = &data[..split.max(1)];
    let plaintext = &data[split..];

    // Encrypt then decrypt must round-trip without panicking
    if let Ok(encrypted) = encrypt_verification_key(shared_key, plaintext) {
        if let Ok(decrypted) = decrypt_verification_key(shared_key, &encrypted) {
            assert_eq!(decrypted, plaintext);
        }
    }

    // Decrypting arbitrary bytes must not panic (it should just return an error)
    let _ = decrypt_verification_key(shared_key, data);

    // Decrypting with a different key must fail or produce different output
    if shared_key.len() > 1 {
        let mut wrong_key = shared_key.to_vec();
        wrong_key[0] ^= 0xff;
        if let Ok(encrypted) = encrypt_verification_key(shared_key, plaintext) {
            let result = decrypt_verification_key(&wrong_key, &encrypted);
            // Should fail; if it somehow succeeds the output must differ from plaintext
            if let Ok(decrypted) = result {
                assert_ne!(decrypted, plaintext.to_vec());
            }
        }
    }
});
