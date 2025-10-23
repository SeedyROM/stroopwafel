# Fuzzing Stroopwafel

This document describes the fuzzing setup for the stroopwafel library using [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz).

## Overview

Fuzzing is a software testing technique that provides invalid, unexpected, or random data as inputs to a program to discover bugs, crashes, and security vulnerabilities. This setup includes comprehensive fuzz targets for all critical components of the library.

## Prerequisites

Fuzzing requires the Rust nightly toolchain:

```bash
rustup install nightly
```

**Note**: You don't need to set nightly as your default - the included scripts automatically use `rustup run nightly`.

## Fuzz Targets

### 1. `fuzz_serialization`
Tests all serialization/deserialization paths:
- MessagePack (binary format)
- Base64 (URL-safe encoding)
- Hexadecimal
- JSON (human-readable format)
- Round-trip serialization/deserialization

### 2. `fuzz_verification`
Tests verification logic and cryptographic operations:
- Stroopwafel creation with random keys and identifiers
- First-party caveat addition and verification
- Third-party caveat creation and discharge binding
- Signature verification and tampering detection
- Incorrect key handling

### 3. `fuzz_predicates`
Tests the predicate parsing and evaluation system:
- All comparison operators: `=`, `!=`, `<`, `>`, `<=`, `>=`
- Numeric comparisons (integers and floats)
- String comparisons
- Edge cases (empty strings, special characters, very long values)
- Malformed predicate handling

### 4. `fuzz_caveats`
Tests caveat addition and complex verification scenarios:
- Adding multiple first-party caveats
- Context-based verification
- Third-party caveats with discharges
- Binding operations (in-place and cloning)
- Batch operations with many caveats

## Running Fuzz Tests

### Quick Test (5 seconds per target)

Run all fuzz targets sequentially for a short duration to smoke-test:

```bash
cd fuzz
./run_all.sh 5
```

### Standard Fuzzing Session (60 seconds per target)

```bash
cd fuzz
./run_all.sh 60
```

Or just use the default:

```bash
cd fuzz
./run_all.sh
```

### Extended Fuzzing (custom duration)

For continuous integration or overnight fuzzing, specify longer durations:

```bash
cd fuzz
./run_all.sh 3600  # 1 hour per target
```

### Parallel Fuzzing (Using Multiple CPU Cores)

By default, libFuzzer uses **half of your CPU cores** for parallel fuzzing. Each worker shares the same corpus, so discoveries by one worker are immediately available to others.

To explicitly control the number of workers:

```bash
# Use 8 parallel workers per target
cd fuzz
./run_all.sh 60 8

# Use only 1 worker (single-threaded)
cd fuzz
./run_all.sh 60 1

# Use default (half of CPU cores)
cd fuzz
./run_all.sh 60
```

**Performance Note**: More workers generally means faster exploration, but each worker needs memory. On a machine with limited RAM, you may want to reduce the worker count.

### Running Individual Targets

To fuzz a specific target:

```bash
rustup run nightly cargo fuzz run fuzz_serialization -- -max_total_time=60
```

Or run indefinitely until stopped with Ctrl+C:

```bash
rustup run nightly cargo fuzz run fuzz_serialization
```

With explicit worker control:

```bash
# Run with 4 workers
rustup run nightly cargo fuzz run fuzz_serialization -- -workers=4

# Run with 4 workers for 120 seconds
rustup run nightly cargo fuzz run fuzz_serialization -- -max_total_time=120 -workers=4
```

### Listing All Targets

```bash
cd fuzz
cargo fuzz list
```

## Understanding Results

### Normal Operation

During fuzzing, you'll see output like:
```
#1234  NEW    cov: 456 ft: 789 corp: 12/345b ...
```

This indicates the fuzzer is working:
- `#1234`: Test case number
- `NEW`: New interesting input found
- `cov: 456`: Code coverage (edges)
- `corp: 12/345b`: Corpus has 12 items totaling 345 bytes

### Finding Issues

If the fuzzer finds a crash or assertion failure:
- The crash will be saved in `fuzz/artifacts/<target_name>/`
- A crash report will be printed to the console
- The test will continue exploring other inputs

### Corpus

Interesting test cases are automatically saved in:
```
fuzz/corpus/<target_name>/
```

These are reused on subsequent runs to improve coverage over time.

## Continuous Fuzzing

For production use, consider:

1. **Run in CI/CD**: Add fuzzing to your CI pipeline with short durations (30-60 seconds)
2. **Dedicated Fuzzing Server**: Run longer sessions on dedicated hardware
3. **OSS-Fuzz**: Submit to [OSS-Fuzz](https://github.com/google/oss-fuzz) for continuous fuzzing by Google

## Tips

- **Start Short**: Use short durations (5-10 seconds) to verify everything works
- **Gradually Increase**: As corpus grows, longer runs find more edge cases
- **Monitor Memory**: Fuzzing is memory-intensive; watch your RAM usage
- **Preserve Corpus**: Keep `fuzz/corpus/` in version control for regression testing

## Troubleshooting

### "error: the option `Z` is only accepted on the nightly compiler"

Make sure you're using `rustup run nightly` or the provided `run_all.sh` script.

### Out of Memory

Reduce the number of parallel jobs:
```bash
rustup run nightly cargo fuzz run <target> -- -workers=1
```

### Fuzzer Hangs

Some complex inputs may take a long time. Set a timeout per input:
```bash
rustup run nightly cargo fuzz run <target> -- -timeout=5
```

## Adding New Fuzz Targets

To create a new fuzz target:

```bash
cd fuzz
cargo fuzz add my_new_target
```

Then edit `fuzz_targets/my_new_target.rs` with your fuzzing logic.

## Resources

- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)
- [cargo-fuzz Documentation](https://github.com/rust-fuzz/cargo-fuzz)
- [libFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)

## Integration with Property Tests

This library also uses property-based testing with [proptest](https://github.com/proptest-rs/proptest) in `tests/proptests.rs`. Fuzzing and property testing complement each other:

- **Fuzzing**: Excellent at finding low-level crashes and memory issues
- **Property Testing**: Better for testing high-level invariants and business logic

Run both regularly for comprehensive test coverage!
