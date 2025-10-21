use stroopwafel::Stroopwafel;
use stroopwafel::verifier::{AcceptAllVerifier, ContextVerifier};

fn main() {
    println!("=== Third-Party Caveats and Discharge Macaroons ===\n");

    // Scenario: A service wants to grant access, but requires authentication
    // from a third-party auth service

    let root_key = b"service_root_secret";
    let auth_verification_key = b"shared_secret_with_auth_service";

    // Step 1: Service creates a stroopwafel with a third-party caveat
    println!("1. Service creates stroopwafel with third-party caveat");
    let mut primary = Stroopwafel::new(root_key, b"session-12345", Some("https://api.service.com"));

    // Add first-party caveat
    primary.add_first_party_caveat(b"resource = /api/documents");

    // Add third-party caveat requiring authentication
    primary.add_third_party_caveat(
        b"user_authenticated",
        auth_verification_key,
        "https://auth.service.com",
    );

    println!(
        "   Primary stroopwafel created with {} caveats",
        primary.caveat_count()
    );
    println!("   - First-party: resource = /api/documents");
    println!("   - Third-party: user_authenticated (at https://auth.service.com)");

    // Step 2: Client tries to verify WITHOUT discharge (should fail)
    println!("\n2. Attempting verification without discharge macaroon...");
    let verifier = ContextVerifier::empty().with("resource", "/api/documents");

    match primary.verify(root_key, &verifier, &[]) {
        Ok(_) => println!("   ✗ Unexpectedly succeeded!"),
        Err(e) => println!("   ✓ Correctly failed: {}", e),
    }

    // Step 3: Client contacts auth service and gets a discharge macaroon
    println!("\n3. Client contacts auth service...");
    println!("   Auth service verifies user credentials...");

    // Auth service creates discharge macaroon
    let mut discharge = Stroopwafel::create_discharge(
        auth_verification_key,
        b"user_authenticated",
        Some("https://auth.service.com"),
    );

    // Auth service can add its own caveats to the discharge
    discharge.add_first_party_caveat(b"auth_level >= 5");

    println!("   ✓ Auth service issues discharge macaroon with caveat: auth_level >= 5");

    // Step 4: Client binds the discharge to the primary stroopwafel
    println!("\n4. Client binds discharge to primary stroopwafel...");
    let bound_discharge = primary.bind_discharge(&discharge);
    println!("   ✓ Discharge bound (signatures cryptographically linked)");

    // Step 5: Client sends primary + bound discharge to service
    println!("\n5. Service verifies both stroopwafels...");

    let full_verifier = ContextVerifier::empty()
        .with("resource", "/api/documents")
        .with("auth_level", "10"); // User has auth level 10

    match primary.verify(root_key, &full_verifier, &[bound_discharge.clone()]) {
        Ok(_) => println!("   ✓ Verification successful! Access granted."),
        Err(e) => println!("   ✗ Verification failed: {}", e),
    }

    // Step 6: Try with insufficient auth level (should fail)
    println!("\n6. Testing with insufficient auth level...");
    let weak_verifier = ContextVerifier::empty()
        .with("resource", "/api/documents")
        .with("auth_level", "3"); // Only level 3 (need >= 5)

    match primary.verify(root_key, &weak_verifier, &[bound_discharge.clone()]) {
        Ok(_) => println!("   ✗ Unexpectedly succeeded!"),
        Err(e) => println!("   ✓ Correctly failed: {}", e),
    }

    // Step 7: Multiple third-party caveats
    println!("\n7. Testing multiple third-party caveats...");

    let payment_key = b"payment_service_key";
    let mut multi_primary = Stroopwafel::new(root_key, b"premium-session", None::<String>);

    multi_primary.add_third_party_caveat(
        b"user_authenticated",
        auth_verification_key,
        "https://auth.service.com",
    );

    multi_primary.add_third_party_caveat(
        b"payment_verified",
        payment_key,
        "https://payments.service.com",
    );

    // Get both discharge macaroons
    let auth_discharge =
        Stroopwafel::create_discharge(auth_verification_key, b"user_authenticated", None::<String>);

    let payment_discharge =
        Stroopwafel::create_discharge(payment_key, b"payment_verified", None::<String>);

    // Prepare for request (binds both)
    let all_stroopwafels =
        multi_primary.prepare_for_request(vec![auth_discharge, payment_discharge]);

    println!(
        "   Created stroopwafel set: {} total",
        all_stroopwafels.len()
    );
    println!("   - 1 primary");
    println!("   - 2 bound discharges");

    // Verify with all discharges
    let permissive_verifier = AcceptAllVerifier;
    match all_stroopwafels[0].verify(root_key, &permissive_verifier, &all_stroopwafels[1..]) {
        Ok(_) => println!("   ✓ All third-party caveats satisfied!"),
        Err(e) => println!("   ✗ Verification failed: {}", e),
    }

    println!("\n=== Example Complete ===");
}
