use proptest::prelude::*;
use stroopwafel::{Stroopwafel, verifier::AcceptAllVerifier};

// Configuration for crypto library: run many more cases than default (100)
// For security-critical code, we want extensive coverage
fn proptest_config() -> ProptestConfig {
    ProptestConfig {
        cases: 10000,
        ..ProptestConfig::default()
    }
}

/// Property: Creating a stroopwafel with the same inputs should always produce the same signature
#[test]
fn prop_signature_deterministic() {
    let config = proptest_config();
    proptest!(config, |(
        root_key in prop::collection::vec(any::<u8>(), 1..128),
        identifier in prop::collection::vec(any::<u8>(), 1..128),
        location in prop::option::of(any::<String>())
    )| {
        let s1 = Stroopwafel::new(&root_key, identifier.clone(), location.clone());
        let s2 = Stroopwafel::new(&root_key, identifier.clone(), location.clone());

        prop_assert_eq!(s1.signature, s2.signature);
        prop_assert_eq!(s1.identifier, s2.identifier);
        prop_assert_eq!(s1.location, s2.location);
    });
}

/// Property: Adding the same caveats in the same order should produce the same signature
#[test]
fn prop_caveat_order_deterministic() {
    let config = proptest_config();
    proptest!(config, |(
        root_key in prop::collection::vec(any::<u8>(), 1..128),
        identifier in prop::collection::vec(any::<u8>(), 1..128),
        caveats in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..64), 0..10)
    )| {
        let mut s1 = Stroopwafel::new(&root_key, identifier.clone(), None::<String>);
        let mut s2 = Stroopwafel::new(&root_key, identifier.clone(), None::<String>);

        for caveat in &caveats {
            s1.add_first_party_caveat(caveat.clone());
            s2.add_first_party_caveat(caveat.clone());
        }

        prop_assert_eq!(s1.signature, s2.signature);
        prop_assert_eq!(s1.caveats.len(), s2.caveats.len());
    });
}

/// Property: Adding caveats in different orders should produce different signatures (unless no caveats)
#[test]
fn prop_caveat_order_matters() {
    let config = proptest_config();
    proptest!(config, |(
        root_key in prop::collection::vec(any::<u8>(), 1..128),
        identifier in prop::collection::vec(any::<u8>(), 1..128),
        caveat1 in prop::collection::vec(any::<u8>(), 1..64),
        caveat2 in prop::collection::vec(any::<u8>(), 1..64)
    )| {
        // Skip if caveats are identical
        prop_assume!(caveat1 != caveat2);

        let mut s1 = Stroopwafel::new(&root_key, identifier.clone(), None::<String>);
        s1.add_first_party_caveat(caveat1.clone());
        s1.add_first_party_caveat(caveat2.clone());

        let mut s2 = Stroopwafel::new(&root_key, identifier.clone(), None::<String>);
        s2.add_first_party_caveat(caveat2.clone());
        s2.add_first_party_caveat(caveat1.clone());

        // Signatures should be different (order matters!)
        prop_assert_ne!(s1.signature, s2.signature);
    });
}

/// Property: A valid stroopwafel without caveats should always verify with the correct root key
#[test]
fn prop_verify_no_caveats() {
    let config = proptest_config();
    proptest!(config, |(
        root_key in prop::collection::vec(any::<u8>(), 1..128),
        identifier in prop::collection::vec(any::<u8>(), 1..128)
    )| {
        let stroopwafel = Stroopwafel::new(&root_key, identifier, None::<String>);
        let verifier = AcceptAllVerifier;

        prop_assert!(stroopwafel.verify(&root_key, &verifier, &[]).is_ok());
    });
}

/// Property: Verification should fail with a different root key
#[test]
fn prop_verify_wrong_key() {
    let config = proptest_config();
    proptest!(config, |(
        root_key in prop::collection::vec(any::<u8>(), 1..128),
        wrong_key in prop::collection::vec(any::<u8>(), 1..128),
        identifier in prop::collection::vec(any::<u8>(), 1..128)
    )| {
        // Skip if keys are the same
        prop_assume!(root_key != wrong_key);

        let stroopwafel = Stroopwafel::new(&root_key, identifier, None::<String>);
        let verifier = AcceptAllVerifier;

        prop_assert!(stroopwafel.verify(&wrong_key, &verifier, &[]).is_err());
    });
}

/// Property: Verification should succeed with correct key and AcceptAllVerifier for any caveats
#[test]
fn prop_verify_with_caveats() {
    let config = proptest_config();
    proptest!(config, |(
        root_key in prop::collection::vec(any::<u8>(), 1..128),
        identifier in prop::collection::vec(any::<u8>(), 1..128),
        caveats in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..64), 0..10)
    )| {
        let mut stroopwafel = Stroopwafel::new(&root_key, identifier, None::<String>);

        for caveat in caveats {
            stroopwafel.add_first_party_caveat(caveat);
        }

        let verifier = AcceptAllVerifier;
        prop_assert!(stroopwafel.verify(&root_key, &verifier, &[]).is_ok());
    });
}

/// Property: JSON serialization roundtrip should preserve the stroopwafel
#[test]
fn prop_json_roundtrip() {
    let config = proptest_config();
    proptest!(config, |(
        root_key in prop::collection::vec(any::<u8>(), 1..128),
        identifier in prop::collection::vec(any::<u8>(), 1..128),
        caveats in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..64), 0..5)
    )| {
        let mut original = Stroopwafel::new(&root_key, identifier, None::<String>);

        for caveat in caveats {
            original.add_first_party_caveat(caveat);
        }

        let json = original.to_json().unwrap();
        let deserialized = Stroopwafel::from_json(&json).unwrap();

        prop_assert_eq!(original, deserialized);
    });
}

/// Property: Base64 serialization roundtrip should preserve the stroopwafel
#[test]
fn prop_base64_roundtrip() {
    let config = proptest_config();
    proptest!(config, |(
        root_key in prop::collection::vec(any::<u8>(), 1..128),
        identifier in prop::collection::vec(any::<u8>(), 1..128),
        caveats in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..64), 0..5)
    )| {
        let mut original = Stroopwafel::new(&root_key, identifier, None::<String>);

        for caveat in caveats {
            original.add_first_party_caveat(caveat);
        }

        let base64 = original.to_base64().unwrap();
        let deserialized = Stroopwafel::from_base64(&base64).unwrap();

        prop_assert_eq!(original, deserialized);
    });
}

/// Property: MessagePack serialization roundtrip should preserve the stroopwafel
#[test]
fn prop_msgpack_roundtrip() {
    let config = proptest_config();
    proptest!(config, |(
        root_key in prop::collection::vec(any::<u8>(), 1..128),
        identifier in prop::collection::vec(any::<u8>(), 1..128),
        caveats in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..64), 0..5)
    )| {
        let mut original = Stroopwafel::new(&root_key, identifier, None::<String>);

        for caveat in caveats {
            original.add_first_party_caveat(caveat);
        }

        let msgpack = original.to_msgpack().unwrap();
        let deserialized = Stroopwafel::from_msgpack(&msgpack).unwrap();

        prop_assert_eq!(original, deserialized);
    });
}

/// Property: Hex serialization roundtrip should preserve the stroopwafel
#[test]
fn prop_hex_roundtrip() {
    let config = proptest_config();
    proptest!(config, |(
        root_key in prop::collection::vec(any::<u8>(), 1..128),
        identifier in prop::collection::vec(any::<u8>(), 1..128),
        caveats in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..64), 0..5)
    )| {
        let mut original = Stroopwafel::new(&root_key, identifier, None::<String>);

        for caveat in caveats {
            original.add_first_party_caveat(caveat);
        }

        let hex = original.to_hex().unwrap();
        let deserialized = Stroopwafel::from_hex(&hex).unwrap();

        prop_assert_eq!(original, deserialized);
    });
}

/// Property: Binding a discharge should change its signature
#[test]
fn prop_discharge_binding_changes_signature() {
    let config = proptest_config();
    proptest!(config, |(
        root_key in prop::collection::vec(any::<u8>(), 1..128),
        verification_key in prop::collection::vec(any::<u8>(), 1..128),
        primary_id in prop::collection::vec(any::<u8>(), 1..128),
        caveat_id in prop::collection::vec(any::<u8>(), 1..128)
    )| {
        let primary = Stroopwafel::new(&root_key, primary_id, None::<String>);
        let discharge = Stroopwafel::create_discharge(&verification_key, caveat_id, None::<String>);

        let original_sig = discharge.signature;
        let bound = primary.bind_discharge(&discharge);

        // Binding should change the signature
        prop_assert_ne!(bound.signature, original_sig);
    });
}

/// Property: Binding the same discharge twice should produce the same result
#[test]
fn prop_discharge_binding_deterministic() {
    let config = proptest_config();
    proptest!(config, |(
        root_key in prop::collection::vec(any::<u8>(), 1..128),
        verification_key in prop::collection::vec(any::<u8>(), 1..128),
        primary_id in prop::collection::vec(any::<u8>(), 1..128),
        caveat_id in prop::collection::vec(any::<u8>(), 1..128)
    )| {
        let primary = Stroopwafel::new(&root_key, primary_id, None::<String>);
        let discharge = Stroopwafel::create_discharge(&verification_key, caveat_id, None::<String>);

        let bound1 = primary.bind_discharge(&discharge);
        let bound2 = primary.bind_discharge(&discharge);

        prop_assert_eq!(bound1.signature, bound2.signature);
    });
}

/// Property: Tampered signature should fail verification
#[test]
fn prop_tampered_signature_fails() {
    let config = proptest_config();
    proptest!(config, |(
        root_key in prop::collection::vec(any::<u8>(), 1..128),
        identifier in prop::collection::vec(any::<u8>(), 1..128),
        bit_position in 0usize..256, // 32 bytes * 8 bits
    )| {
        let mut stroopwafel = Stroopwafel::new(&root_key, identifier, None::<String>);

        // Flip one bit in the signature
        let byte_pos = bit_position / 8;
        let bit_pos = bit_position % 8;
        stroopwafel.signature[byte_pos] ^= 1 << bit_pos;

        let verifier = AcceptAllVerifier;
        prop_assert!(stroopwafel.verify(&root_key, &verifier, &[]).is_err());
    });
}

/// Property: Caveat count should match the number of caveats added
#[test]
fn prop_caveat_count() {
    let config = proptest_config();
    proptest!(config, |(
        root_key in prop::collection::vec(any::<u8>(), 1..128),
        identifier in prop::collection::vec(any::<u8>(), 1..128),
        caveats in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..64), 0..20)
    )| {
        let mut stroopwafel = Stroopwafel::new(&root_key, identifier, None::<String>);

        prop_assert_eq!(stroopwafel.caveat_count(), 0);
        prop_assert!(stroopwafel.is_unrestricted());

        for caveat in &caveats {
            stroopwafel.add_first_party_caveat(caveat.clone());
        }

        prop_assert_eq!(stroopwafel.caveat_count(), caveats.len());
        if !caveats.is_empty() {
            prop_assert!(!stroopwafel.is_unrestricted());
        }
    });
}
