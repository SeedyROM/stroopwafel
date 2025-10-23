#![no_main]

use libfuzzer_sys::fuzz_target;
use stroopwafel::{Stroopwafel, verifier::{ContextVerifier, FnVerifier}};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Split data for different purposes
    let root_key = b"fuzz_root_key";
    let identifier = b"fuzz_identifier";

    // Create stroopwafel
    let mut token = Stroopwafel::new(root_key, identifier, None::<String>);

    // Add various caveats using the fuzz data
    for chunk in data.chunks(16) {
        if chunk.is_empty() {
            continue;
        }

        // Try adding as first-party caveat
        token.add_first_party_caveat(chunk);

        // If we can convert to UTF-8, try with verifiers
        if let Ok(s) = std::str::from_utf8(chunk) {
            // Test with ContextVerifier
            let parts: Vec<&str> = s.split('=').collect();
            if parts.len() == 2 {
                let key = parts[0].trim();
                let value = parts[1].trim();

                if !key.is_empty() && !value.is_empty() {
                    let verifier = ContextVerifier::empty().with(key, value);
                    let _ = token.verify(root_key, &verifier, &[]);

                    // Try with wrong value
                    let wrong_verifier = ContextVerifier::empty().with(key, "wrong_value");
                    let _ = token.verify(root_key, &wrong_verifier, &[]);
                }
            }
        }
    }

    // Test third-party caveats with fuzz data
    if data.len() >= 32 {
        let vk = &data[0..16];
        let caveat_id = &data[16..32];

        token.add_third_party_caveat(caveat_id, vk, "https://fuzz.test");

        // Create discharge
        let mut discharge = Stroopwafel::create_discharge(vk, caveat_id, Some("https://fuzz.test"));

        // Add caveats to discharge using remaining data
        if data.len() > 32 {
            for chunk in data[32..].chunks(8) {
                if !chunk.is_empty() {
                    discharge.add_first_party_caveat(chunk);
                }
            }
        }

        // Bind and verify
        let bound = token.bind_discharge(&discharge);
        let verifier = FnVerifier::new(|_| Ok(()));
        let _ = token.verify(root_key, &verifier, &[bound]);
    }

    // Test prepare_for_request with multiple discharges
    if data.len() >= 48 {
        let discharges: Vec<Stroopwafel> = (0..3)
            .map(|i| {
                let offset = i * 16;
                if offset + 16 <= data.len() {
                    let vk = &data[offset..offset + 8];
                    let cid = &data[offset + 8..offset + 16];
                    Stroopwafel::create_discharge(vk, cid, None::<String>)
                } else {
                    Stroopwafel::create_discharge(b"default", b"default", None::<String>)
                }
            })
            .collect();

        let _ = token.prepare_for_request(discharges);
    }

    // Test binding in-place
    if data.len() >= 16 {
        let mut discharge = Stroopwafel::create_discharge(
            &data[0..8],
            &data[8..16],
            None::<String>
        );
        token.bind_discharge_inplace(&mut discharge);
    }

    // Test serialization round-trips after adding caveats
    if let Ok(msgpack) = token.to_msgpack() {
        let _ = Stroopwafel::from_msgpack(&msgpack);
    }

    if let Ok(json) = token.to_json() {
        let _ = Stroopwafel::from_json(&json);
    }

    // Test with lots of caveats
    let mut many_caveats_token = Stroopwafel::new(root_key, identifier, None::<String>);
    for i in 0..100.min(data.len()) {
        many_caveats_token.add_first_party_caveat(&data[i..i+1]);
    }

    let verifier = FnVerifier::new(|_| Ok(()));
    let _ = many_caveats_token.verify(root_key, &verifier, &[]);

    // Check caveat count
    let _ = many_caveats_token.caveat_count();
    let _ = many_caveats_token.is_unrestricted();
});
