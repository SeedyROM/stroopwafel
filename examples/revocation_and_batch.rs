use stroopwafel::{
    decrypt_verification_key, encrypt_verification_key, RevocationList, Stroopwafel,
    verifier::AcceptAllVerifier,
};

fn main() {
    println!("=== Revocation, Batch Verification, and Encryption ===\n");

    let root_key = b"example-root-secret-key";

    // --- Encryption helpers ---
    println!("1. Third-party caveat with encrypted verification key");

    let shared_secret = b"secret-known-by-issuer-and-auth-service";
    let verification_key = b"random-per-request-verification-key";

    let encrypted_vk = encrypt_verification_key(shared_secret, verification_key).unwrap();

    let mut primary = Stroopwafel::new(root_key, b"session-abc", Some("https://api.example.com"));
    primary.add_first_party_caveat(b"resource ~ /documents/*");
    primary.add_third_party_caveat(b"auth-check", encrypted_vk.as_slice(), "https://auth.example.com");

    // Auth service decrypts the key and issues a discharge
    let decrypted_vk = decrypt_verification_key(shared_secret, &encrypted_vk).unwrap();
    let discharge =
        Stroopwafel::create_discharge(&decrypted_vk, b"auth-check", Some("https://auth.example.com"));
    let bound = primary.bind_discharge(&discharge);

    let verifier = stroopwafel::verifier::ContextVerifier::empty()
        .with("resource", "/documents/readme.md");

    match primary.verify(root_key, &verifier, std::slice::from_ref(&bound)) {
        Ok(_) => println!("   Verification passed with encrypted third-party caveat"),
        Err(e) => println!("   Verification failed: {e}"),
    }

    // Wrong shared secret should fail to decrypt
    let wrong_secret = b"not-the-right-secret";
    match decrypt_verification_key(wrong_secret, &encrypted_vk) {
        Ok(_) => println!("   Unexpectedly decrypted with wrong secret"),
        Err(_) => println!("   Decryption with wrong secret correctly rejected"),
    }

    // --- Revocation ---
    println!("\n2. Revocation with verify_checked");

    let t1 = Stroopwafel::new(root_key, b"session-abc", None::<String>);
    let t2 = Stroopwafel::new(root_key, b"session-xyz", None::<String>);

    let mut revoked = RevocationList::new();

    match t1.verify_checked(root_key, &AcceptAllVerifier, &[], &revoked) {
        Ok(_) => println!("   session-abc passes (not yet revoked)"),
        Err(e) => println!("   session-abc failed: {e}"),
    }

    revoked.revoke(b"session-abc");

    match t1.verify_checked(root_key, &AcceptAllVerifier, &[], &revoked) {
        Ok(_) => println!("   session-abc unexpectedly passed"),
        Err(e) => println!("   session-abc correctly rejected: {e}"),
    }

    match t2.verify_checked(root_key, &AcceptAllVerifier, &[], &revoked) {
        Ok(_) => println!("   session-xyz passes (different session, not revoked)"),
        Err(e) => println!("   session-xyz failed: {e}"),
    }

    // --- Batch verification ---
    println!("\n3. Batch verification");

    let tokens: Vec<Stroopwafel> = (1..=5)
        .map(|i| Stroopwafel::new(root_key, format!("batch-session-{i}").as_bytes(), None::<String>))
        .collect();

    let results = Stroopwafel::verify_batch(tokens.iter(), root_key, &AcceptAllVerifier, &[]);
    let passed = results.iter().filter(|r| r.is_ok()).count();
    println!("   verify_batch: {passed}/{} passed", results.len());

    match Stroopwafel::verify_all(tokens.iter(), root_key, &AcceptAllVerifier, &[]) {
        Ok(_) => println!("   verify_all: all passed"),
        Err(e) => println!("   verify_all: failed on first error: {e}"),
    }

    // Tamper one token and show verify_all stops early
    let mut mixed = tokens.clone();
    mixed[2].signature[0] ^= 0xff;

    match Stroopwafel::verify_all(mixed.iter(), root_key, &AcceptAllVerifier, &[]) {
        Ok(_) => println!("   verify_all unexpectedly passed with tampered token"),
        Err(e) => println!("   verify_all stopped at tampered token: {e}"),
    }

    println!("\n=== Example Complete ===");
}
