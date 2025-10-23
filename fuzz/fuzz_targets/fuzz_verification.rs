#![no_main]

use libfuzzer_sys::fuzz_target;
use stroopwafel::{Stroopwafel, verifier::AcceptAllVerifier};

fuzz_target!(|data: &[u8]| {
    // Need at least some data to work with
    if data.len() < 10 {
        return;
    }

    // Split the data into root key and identifier
    let split_point = data.len() / 2;
    let root_key = &data[..split_point];
    let identifier = &data[split_point..];

    // Create a basic stroopwafel
    let mut token = Stroopwafel::new(root_key, identifier, None::<String>);

    // Try to add first-party caveats using parts of the data
    let caveat_size = data.len() / 4;
    if caveat_size > 0 {
        for chunk in data.chunks(caveat_size) {
            if !chunk.is_empty() {
                token.add_first_party_caveat(chunk);
            }
        }
    }

    // Always try to verify with the correct root key
    let verifier = AcceptAllVerifier;
    let _ = token.verify(root_key, &verifier, &[]);

    // Try to verify with wrong keys (should fail)
    if root_key.len() > 1 {
        let mut wrong_key = root_key.to_vec();
        wrong_key[0] ^= 0xFF;
        let _ = token.verify(&wrong_key, &verifier, &[]);
    }

    // Try creating a discharge and binding it
    if data.len() > 20 {
        let vk_split = data.len() / 3;
        let verification_key = &data[..vk_split];
        let caveat_id = &data[vk_split..vk_split * 2];

        // Add third-party caveat
        token.add_third_party_caveat(caveat_id, verification_key, "http://example.com");

        // Create and bind discharge
        let discharge = Stroopwafel::create_discharge(
            verification_key,
            caveat_id,
            Some("http://example.com")
        );
        let bound_discharge = token.bind_discharge(&discharge);

        // Try to verify with discharge
        let _ = token.verify(root_key, &verifier, &[bound_discharge]);
    }

    // Test prepare_for_request
    let _ = token.prepare_for_request(vec![]);

    // Test signature tampering resistance
    let mut tampered = token.clone();
    if !tampered.signature.is_empty() {
        tampered.signature[0] ^= 0xFF;
        let _ = tampered.verify(root_key, &verifier, &[]);
    }
});
