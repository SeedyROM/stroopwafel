use stroopwafel::verifier::ContextVerifier;
use stroopwafel::Stroopwafel;

fn main() {
    println!("=== Stroopwafel Basic Usage Example ===\n");

    // Step 1: Mint a new stroopwafel
    let root_key = b"this is a super secret key";
    let mut stroopwafel = Stroopwafel::new(
        root_key,
        b"user-session-12345",
        Some("https://api.example.com"),
    );

    println!("1. Created stroopwafel with identifier: {:?}",
        String::from_utf8_lossy(&stroopwafel.identifier));

    // Step 2: Add first-party caveats (restrictions)
    stroopwafel.add_first_party_caveat(b"account = alice");
    stroopwafel.add_first_party_caveat(b"action = read");
    stroopwafel.add_first_party_caveat(b"resource = /api/documents");

    println!("\n2. Added caveats:");
    for (i, caveat) in stroopwafel.caveats.iter().enumerate() {
        println!("   {}. {}", i + 1, String::from_utf8_lossy(&caveat.caveat_id));
    }

    // Step 3: Serialize the stroopwafel for transmission
    let json = stroopwafel.to_json().unwrap();
    let base64 = stroopwafel.to_base64().unwrap();

    println!("\n3. Serialized formats:");
    println!("   JSON (truncated): {}...", &json[..80.min(json.len())]);
    println!("   Base64: {}", base64);

    // Step 4: Deserialize and verify
    let received = Stroopwafel::from_base64(&base64).unwrap();

    println!("\n4. Received stroopwafel, verifying...");

    // Create a context that matches the caveats
    let verifier = ContextVerifier::empty()
        .with("account", "alice")
        .with("action", "read")
        .with("resource", "/api/documents");

    match received.verify(root_key, &verifier, &[]) {
        Ok(_) => println!("   ✓ Verification successful!"),
        Err(e) => println!("   ✗ Verification failed: {}", e),
    }

    // Step 5: Try with wrong context
    println!("\n5. Testing with wrong account...");
    let wrong_verifier = ContextVerifier::empty()
        .with("account", "bob") // Wrong account!
        .with("action", "read")
        .with("resource", "/api/documents");

    match received.verify(root_key, &wrong_verifier, &[]) {
        Ok(_) => println!("   ✗ Unexpectedly succeeded!"),
        Err(e) => println!("   ✓ Correctly failed: {}", e),
    }

    // Step 6: Numeric comparisons
    println!("\n6. Testing numeric comparisons...");
    let mut time_limited = Stroopwafel::new(root_key, b"session-with-expiry", None::<String>);
    time_limited.add_first_party_caveat(b"count < 100");
    time_limited.add_first_party_caveat(b"level >= 5");

    let numeric_verifier = ContextVerifier::empty()
        .with("count", "50")   // 50 < 100 ✓
        .with("level", "10");  // 10 >= 5 ✓

    match time_limited.verify(root_key, &numeric_verifier, &[]) {
        Ok(_) => println!("   ✓ Numeric verification successful!"),
        Err(e) => println!("   ✗ Numeric verification failed: {}", e),
    }

    println!("\n=== Example Complete ===");
}
