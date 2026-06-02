# Stroopwafel 🧇

[![GitHub](https://img.shields.io/badge/github-stroopwafel-8da0cb?logo=github)](https://github.com/SeedyROM/stroopwafel)
[![crates.io version](https://img.shields.io/crates/v/stroopwafel.svg)](https://crates.io/crates/stroopwafel)
[![docs.rs docs](https://docs.rs/stroopwafel/badge.svg)](https://docs.rs/stroopwafel)
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)
[![Apache 2.0 license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE-APACHE)

A Rust implementation of **Macaroons**: authorization tokens with contextual caveats for decentralized authorization.

> **Why "Stroopwafel"?** Because Dutch cookies are better than French macarons! Plus, it's more fun to say.

## Overview

Stroopwafels are bearer tokens that support flexible, decentralized authorization through **caveats**: contextual restrictions that can be added to tokens without invalidating their cryptographic integrity. Based on the paper ["Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud"](https://research.google/pubs/pub41892/) by Birgisson et al. (NDSS 2014).

### Features

- Delegate authority without central coordination
- Add restrictions like time limits, account permissions, IP ranges
- HMAC-SHA3-256 signature chains prevent tampering
- First and third-party caveats: verify locally or delegate to external services
- Multiple serialization formats: JSON, MessagePack, Base64, Hex
- Zero-allocation signature validation
- Type-safe API via Rust's type system

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
stroopwafel = "0.1.0"
```

### Basic example

```rust ignore
use stroopwafel::{Stroopwafel, verifier::ContextVerifier};

// 1. Mint a new token (server-side)
let root_key = b"this is our super secret key";
let mut token = Stroopwafel::new(
    root_key,
    b"user:alice",
    Some("https://api.example.com")
);

// 2. Add restrictions
token.add_first_party_caveat(b"account = alice");
token.add_first_party_caveat(b"action = read");
token.add_first_party_caveat(b"expires < 2025-12-31T23:59:59Z");

// 3. Serialize for transmission
let serialized = token.to_base64()?;

// 4. Verify the token (on any service with the root key)
let verifier = ContextVerifier::empty()
    .with("account", "alice")
    .with("action", "read")
    .with("expires", "2025-06-01T00:00:00Z");

token.verify(root_key, &verifier, &[])?;
```

## Core concepts

### Minting

Create a new stroopwafel with a secret root key:

```rust ignore
let root_key = b"secret-key-only-server-knows";
let token = Stroopwafel::new(root_key, b"user-id-123", None::<String>);
```

### First-party caveats

Add restrictions verified by your service:

```rust ignore
token.add_first_party_caveat(b"account = alice");
token.add_first_party_caveat(b"action = read");
token.add_first_party_caveat(b"resource = /documents/*");
```

### Third-party caveats

Delegate verification to external services. The verification key must be encrypted before embedding it in the caveat — see [Third-party caveat encryption](#third-party-caveat-encryption) for the built-in helpers.

```rust ignore
use stroopwafel::encryption::encrypt_verification_key;

let shared_secret = b"key-shared-between-issuer-and-auth-service";
let vk = b"fresh-random-verification-key";
let encrypted_vk = encrypt_verification_key(shared_secret, vk)?;

token.add_third_party_caveat(b"auth-service-check", encrypted_vk, "https://auth.example.com");

// Third party decrypts the verification key and creates a discharge macaroon
let discharge = Stroopwafel::create_discharge(
    &verification_key,
    b"auth-service-check",
    Some("https://auth.example.com"),
);

// Bind for use
let prepared = token.prepare_for_request(vec![discharge]);
```

### Verification

Verify tokens with custom logic:

```rust ignore
use stroopwafel::verifier::{ContextVerifier, FnVerifier};

// Context-based verification (recommended)
let verifier = ContextVerifier::empty()
    .with("user", "alice")
    .with("role", "admin")
    .with("level", "10");

token.verify(root_key, &verifier, &[])?;

// Custom verification logic
let verifier = FnVerifier::new(|predicate| {
    // Your custom verification logic
    if predicate.starts_with(b"custom:") {
        // Check custom rules...
        Ok(())
    } else {
        Err(StroopwafelError::CaveatViolation("Unknown caveat".into()))
    }
});
```

## Predicate system

Built-in support for common comparison operators:

| Operator | Description | Example |
|----------|-------------|---------|
| `=` | Equality | `account = alice` |
| `!=` | Inequality | `status != banned` |
| `<` | Less than | `age < 18` |
| `>` | Greater than | `level > 5` |
| `<=` | Less than or equal | `requests <= 100` |
| `>=` | Greater than or equal | `score >= 50` |
| `~` | Glob match | `resource ~ /api/*` |
| `!~` | Glob not-match | `resource !~ /internal/*` |

Both numeric and string comparisons are supported:

```rust ignore
token.add_first_party_caveat(b"age >= 21");        // Numeric
token.add_first_party_caveat(b"name = alice");     // String
token.add_first_party_caveat(b"time < 2025-12-31"); // String (ISO 8601)
```

### Glob / prefix matching

The `~` operator matches a context value against a glob pattern. Supported wildcards:

- `*` — matches zero or more characters
- `?` — matches exactly one character

```rust ignore
// Restrict access to a path prefix
token.add_first_party_caveat(b"resource ~ /documents/*");

// Allow only versioned API paths
token.add_first_party_caveat(b"path ~ /api/v?/*");

// Block internal resources
token.add_first_party_caveat(b"resource !~ /internal/*");
```

Verify by providing the actual resource in the context:

```rust ignore
let verifier = ContextVerifier::empty()
    .with("resource", "/documents/readme.md");

token.verify(root_key, &verifier, &[])?; // passes: /documents/readme.md matches /documents/*
```

## Third-party caveat encryption

The library provides helpers for encrypting verification keys before passing them to
`add_third_party_caveat`. Both sides share a secret; the issuer encrypts, the third
party decrypts to recover the verification key:

```rust ignore
use stroopwafel::encryption::{encrypt_verification_key, decrypt_verification_key};

// Issuer side: encrypt the verification key with the shared secret
let shared_secret = b"key-shared-between-issuer-and-auth-service";
let vk = b"fresh-random-verification-key";
let encrypted_vk = encrypt_verification_key(shared_secret, vk)?;

token.add_third_party_caveat(b"auth-check", encrypted_vk, "https://auth.example.com");

// Third-party side: decrypt to get the verification key, then create a discharge
let verification_key = decrypt_verification_key(shared_secret, &encrypted_vk)?;
let discharge = Stroopwafel::create_discharge(&verification_key, b"auth-check", Some("https://auth.example.com"));
```

Encryption uses **ChaCha20-Poly1305** with a random 96-bit nonce per call. The shared
secret can be any length; it is key-derived (HMAC-SHA3-256) to exactly 32 bytes before
use. The output format is `nonce (12 bytes) || ciphertext+tag`.

## Revocation

Check whether a token has been revoked before verifying it by using
`verify_checked` with a [`RevocationChecker`]:

```rust ignore
use stroopwafel::revocation::RevocationList;

let mut revoked = RevocationList::new();
revoked.revoke(b"session-to-invalidate");

// verify_checked rejects revoked identifiers before any cryptographic work
token.verify_checked(root_key, &verifier, &[], &revoked)?;
```

The built-in `RevocationList` is an in-memory `HashSet`. For production use,
implement the `RevocationChecker` trait against your own persistent store (Redis,
database, etc.):

```rust ignore
use stroopwafel::RevocationChecker;

struct MyStore { /* ... */ }

impl RevocationChecker for MyStore {
    fn is_revoked(&self, identifier: &[u8]) -> bool {
        // query your store
        false
    }
}
```

## Batch verification

Verify multiple tokens sharing the same root key with `verify_batch` (collects all
results) or `verify_all` (fails fast):

```rust ignore
// Collect all results — useful for audit logging
let results = Stroopwafel::verify_batch([&t1, &t2, &t3], root_key, &verifier, &[]);
for (i, result) in results.iter().enumerate() {
    if let Err(e) = result {
        eprintln!("Token {i} failed: {e}");
    }
}

// Fail on first error
Stroopwafel::verify_all([&t1, &t2, &t3], root_key, &verifier, &[])?;
```

## Performance and allocation control

Stroopwafel provides both convenient and allocation-conscious APIs:

```rust ignore
// Convenient API (clones primary)
let prepared = primary.prepare_for_request(vec![discharge1, discharge2]);

// Zero-clone API (consumes primary)
let prepared = Stroopwafel::prepare_for_request_with(primary, vec![discharge1, discharge2]);

// In-place binding (for manual control)
let mut discharge = create_discharge(...);
primary.bind_discharge_inplace(&mut discharge);
```

`verify()` operates on references and only allocates 32 bytes per caveat for signature chain reconstruction.

## Serialization

Multiple formats supported:

```rust ignore
// MessagePack (binary, compact)
let bytes = token.to_msgpack()?;
let token = Stroopwafel::from_msgpack(&bytes)?;

// Base64 (URL-safe, for HTTP headers)
let b64 = token.to_base64()?;
let token = Stroopwafel::from_base64(&b64)?;

// JSON (human-readable)
let json = token.to_json_pretty()?;
let token = Stroopwafel::from_json(&json)?;

// Hex (debugging)
let hex = token.to_hex()?;
let token = Stroopwafel::from_hex(&hex)?;
```

## Security considerations

### Best practices

1. **Keep root keys secret**: only the issuing service should know the root key
2. **Use HTTPS**: always transmit tokens over encrypted connections
3. **Validate caveats carefully**: ensure your verifier logic is correct
4. **Limit token lifetime**: add time-based caveats to prevent indefinite use
5. **Bind discharge macaroons**: always use `prepare_for_request()` to bind discharges
6. **Encrypt third-party verification keys**: the `verification_key_id` parameter in `add_third_party_caveat()` must contain an encrypted key, not plaintext. This library provides cryptographic primitives but does not handle key encryption.

### Cryptographic details

| Detail | Value |
|--------|-------|
| Algorithm | HMAC-SHA3-256 (Keccak-256) |
| Signature size | 32 bytes |
| Chaining | Each caveat updates the signature via HMAC |
| Timing attacks | Constant-time equality prevents timing side-channels |
| Caveats | Not encrypted (don't put secrets in them!) |

## Examples

See the [`examples/`](examples/) directory:

- [`basic_usage.rs`](examples/basic_usage.rs) - Complete end-to-end workflow

Run examples:

```bash
cargo run --example basic_usage
```

## Performance

Benchmarks (Apple M1, example results):

```ignore
create_stroopwafel     1.2 µs
verify_stroopwafel     2.4 µs
serialize_msgpack      800 ns
deserialize_msgpack    1.1 µs
```

Run benchmarks:

```bash
cargo bench
```

## Testing

### Unit and integration tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_verify_valid_stroopwafel
```

### Property-based testing

Property tests verify cryptographic invariants and roundtrip properties:

```bash
# Run property tests (10,000 iterations per test by default)
cargo test --test proptests

# Run with verbose output
cargo test --test proptests -- --nocapture
```

Property tests cover:
- Serialization/deserialization roundtrips across all formats
- Signature verification invariants
- Caveat addition preserves validity
- Discharge binding correctness
- Time-based expiration edge cases

### Fuzz testing

```bash
# Quick smoke test (5 seconds per target)
cd fuzz && ./run_all.sh 5

# Standard fuzzing session (60 seconds per target)
cd fuzz && ./run_all.sh
```

See [FUZZ.md](FUZZ.md) for detailed fuzzing documentation.

## Roadmap

- [x] Core stroopwafel creation and verification
- [x] First-party caveats with predicates
- [x] Third-party caveats with discharge macaroons
- [x] Multiple serialization formats
- [x] Context-based verification
- [x] Allocation-conscious API (in-place binding, zero-clone preparation)
- [x] Property-based testing (proptest)
- [x] Fuzz testing (cargo-fuzz)
- [x] Verification key encryption helpers for third-party caveats (ChaCha20-Poly1305)
- [x] Revocation support (`RevocationChecker` trait + `RevocationList`)
- [x] Batch verification (`verify_batch` / `verify_all`)
- [x] Glob / prefix predicate matching (`~` and `!~` operators)

## Contributing

### Development setup

This project uses [pre-commit](https://pre-commit.com) to enforce formatting, linting, and tests before commits and pushes.

Install `pre-commit` (once, globally):

```bash
pip install pre-commit
# or via Homebrew
brew install pre-commit
```

Then install the hooks for this repo:

```bash
pre-commit install            # runs on every commit (fmt + clippy)
pre-commit install --hook-type pre-push  # runs cargo test on push
```

Hooks that run on **commit**:
- `trailing-whitespace`, `end-of-file-fixer`, `check-yaml`, `check-toml`, `check-merge-conflict`, `check-added-large-files`
- `cargo fmt` — auto-formats changed `.rs` / `.toml` files
- `cargo clippy --fix` — applies lint fixes; fails the commit if warnings remain

Hook that runs on **push**:
- `cargo test --all-features --all-targets`

To run all hooks manually without committing:

```bash
pre-commit run --all-files
```

### Submitting changes

Pull requests welcome. Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure `cargo test` and `cargo clippy` pass
5. Submit a pull request

## License

Dual licensed under your choice of:

- Apache License, Version 2.0 (<http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license (<http://opensource.org/licenses/MIT>)

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.

## References

- [Macaroons Paper (NDSS 2014)](https://research.google/pubs/pub41892/)
- [Google Research Blog Post](https://research.googleblog.com/2014/12/macaroons-cookies-with-contextual.html)
- [libmacaroons (C implementation)](https://github.com/rescrv/libmacaroons)

## Acknowledgments

Based on the original Macaroons design by Arnar Birgisson, Joe Gibbs Politz, Úlfar Erlingsson, Ankur Taly, Michael Vrable, and Mark Lentczner.

---

**Made with 🧇 and Rust**
