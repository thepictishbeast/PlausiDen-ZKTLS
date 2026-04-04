# plausiden-zktls — general-purpose zkTLS identity verification toolkit

# Run all tests
test:
    cargo test

# Run tests with output visible
test-verbose:
    cargo test -- --nocapture

# Format all code
fmt:
    cargo fmt

# Run clippy lints (warnings are errors)
lint:
    cargo clippy -- -D warnings

# Build release binaries
build:
    cargo build --release

# Generate and open documentation
docs:
    cargo doc --no-deps --open

# Audit dependencies for known vulnerabilities
audit:
    cargo audit

# Run the full check suite: format, lint, test, build
check-all: fmt lint test build
