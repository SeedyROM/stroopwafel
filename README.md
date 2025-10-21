# Stroopwafel 🍪

A Rust implementation of **Macaroons** - authorization tokens with contextual caveats for decentralized authorization.

> **Why "Stroopwafel"?** Because Dutch cookies are better than French macarons! Plus, it's more fun to say.

## Overview

Stroopwafels are bearer tokens that enable flexible, decentralized authorization through **caveats** - contextual restrictions that can be added to tokens without invalidating their cryptographic integrity. Based on the paper ["Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud"](https://research.google/pubs/pub41892/) by Birgisson et al. (NDSS 2014).

### Key Features

- **Decentralized Authorization**: Delegate authority without central coordination
- **Contextual Caveats**: Add restrictions like time limits, account permissions, IP ranges
- **Cryptographic Integrity**: HMAC-SHA3-256 signature chains prevent tampering
- **First & Third-Party Caveats**: Verify locally or delegate to external services
- **Multiple Serialization Formats**: JSON, MessagePack, Base64, Hex
- **Zero-Copy Verification**: Efficient signature validation
- **Type-Safe API**: Leverage Rust's type system for security

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
stroopwafel = "0.1.0"
```

### Basic Example

```rust,ignore
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

## Core Concepts

### Minting

Create a new stroopwafel with a secret root key:

```rust,ignore
let root_key = b"secret-key-only-server-knows";
let token = Stroopwafel::new(root_key, b"user-id-123", None::<String>);
```

### First-Party Caveats

Add restrictions verified by your service:

```rust,ignore
token.add_first_party_caveat(b"account = alice");
token.add_first_party_caveat(b"action = read");
token.add_first_party_caveat(b"resource = /documents/*");
```

### Third-Party Caveats

Delegate verification to external services:

```rust,ignore
token.add_third_party_caveat(
    b"auth-service-check",
    b"encrypted-verification-key",
    "https://auth.example.com"
);

// Third party creates discharge macaroon
let discharge = Stroopwafel::create_discharge(
    b"encrypted-verification-key",
    b"auth-service-check",
    Some("https://auth.example.com")
);

// Bind for use
let prepared = token.prepare_for_request(vec![discharge]);
```

### Verification

Verify tokens with custom logic:

```rust,ignore
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

## Predicate System

Built-in support for common comparison operators:

| Operator | Description | Example |
|----------|-------------|---------|
| `=` | Equality | `account = alice` |
| `!=` | Inequality | `status != banned` |
| `<` | Less than | `age < 18` |
| `>` | Greater than | `level > 5` |
| `<=` | Less than or equal | `requests <= 100` |
| `>=` | Greater than or equal | `score >= 50` |

Both numeric and string comparisons are supported:

```rust,ignore
token.add_first_party_caveat(b"age >= 21");        // Numeric
token.add_first_party_caveat(b"name = alice");     // String
token.add_first_party_caveat(b"time < 2025-12-31"); // String (ISO 8601)
```

## Serialization

Multiple formats supported:

```rust,ignore
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

## Security Considerations

### Best Practices

1. **Keep root keys secret**: Only the issuing service should know the root key
2. **Use HTTPS**: Always transmit tokens over encrypted connections
3. **Validate caveats carefully**: Ensure your verifier logic is correct
4. **Limit token lifetime**: Add time-based caveats to prevent indefinite use
5. **Bind discharge macaroons**: Always use `prepare_for_request()` to bind discharges

### Cryptographic Details

- **Algorithm**: HMAC-SHA3-256 (Keccak-256)
- **Signature Size**: 32 bytes
- **Chaining**: Each caveat updates the signature via HMAC
- **No Encryption**: Caveats are not encrypted (don't put secrets in them!)

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

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_verify_valid_stroopwafel
```

Current test coverage: **62 unit tests + 15 doc tests**

## Roadmap

- [x] Core stroopwafel creation and verification
- [x] First-party caveats with predicates
- [x] Third-party caveats (basic support)
- [x] Multiple serialization formats
- [x] Context-based verification
- [ ] Full discharge macaroon workflow
- [ ] Property-based testing
- [ ] Revocation support
- [ ] Batch verification

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure `cargo test` and `cargo clippy` pass
5. Submit a pull request

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## References

- [Macaroons Paper (NDSS 2014)](https://research.google/pubs/pub41892/)
- [Google Research Blog Post](https://research.googleblog.com/2014/12/macaroons-cookies-with-contextual.html)
- [libmacaroons (C implementation)](https://github.com/rescrv/libmacaroons)

## Acknowledgments

Based on the original Macaroons design by Arnar Birgisson, Joe Gibbs Politz, Úlfar Erlingsson, Ankur Taly, Michael Vrable, and Mark Lentczner.

---

**Made with 🍪 and Rust**
