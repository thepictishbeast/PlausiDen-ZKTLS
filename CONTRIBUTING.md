# Contributing to plausiden-zktls

Thank you for your interest in contributing to plausiden-zktls. This toolkit is a general-purpose public good and contributions from the community make it stronger.

## Development Environment

### Prerequisites

- **Rust 1.75+** -- install via [rustup](https://rustup.rs/)
- **Just** -- command runner, install via `cargo install just` or your system package manager
- **cargo-audit** -- for dependency vulnerability scanning, install via `cargo install cargo-audit`

### Getting Started

```bash
git clone https://github.com/thepictishbeast/plausiden-zktls.git
cd plausiden-zktls

# Build everything
just build

# Run all tests
just test

# Run the full check suite (format, lint, test, build)
just check-all
```

### Project Structure

```
plausiden-zktls/
  zktls-core/         Core types (no I/O, no crypto ops)
  zktls-notary/       Notary service
  zktls-verifier/     Proof verification
  zktls-templates/    Template definitions
```

## Code Style

### Formatting

All code must pass `cargo fmt --check`. Run `just fmt` before committing.

### Linting

All code must pass `cargo clippy -- -D warnings`. Run `just lint` to check.

### Error Handling

- Use `thiserror` for library error types in all crates.
- Use `anyhow` only in application/binary code (e.g., the notary server binary).
- Never use `unwrap()` in library code. If you must use it in tests, add a comment explaining why it is safe.
- Prefer the `?` operator for error propagation.

### Documentation

- Every public function, struct, enum, and module must have a `///` doc comment.
- Doc comments explain **what** the item does, **what** the parameters mean, **what** it returns, and **when** it can fail.
- Include code examples in doc comments for key APIs.

### Testing

- Every public function must have at least one test.
- Use `#[cfg(test)] mod tests` in each source file.
- Use descriptive test names that explain what is being tested.
- For cryptographic code, use property-based testing with `proptest`.

### Comments

- Write comments explaining **why**, not **what**.
- Use `// TODO:` for known future work, with a brief description.

## Submitting Changes

### Branch Naming

- `feature/*` for new features
- `fix/*` for bug fixes
- `docs/*` for documentation changes

### Pull Request Process

1. Fork the repository and create your branch from `main`.
2. Write or update tests for your changes.
3. Run `just check-all` and ensure everything passes.
4. Update `CHANGELOG.md` with your changes under the `[Unreleased]` section.
5. If your change affects the architecture, update `ARCHITECTURE.md`.
6. Open a pull request with a clear description of the change and its motivation.

### Commit Messages

Write clear, concise commit messages. Use the imperative mood ("Add feature" not "Added feature"). Keep the first line under 72 characters. Add a blank line and then a longer description if needed.

### Issue Labels

- `good first issue` -- suitable for newcomers to the project
- `help wanted` -- we would appreciate community help
- `security` -- security-related changes (see SECURITY.md)
- `breaking` -- introduces a breaking API change

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to uphold this code. Report unacceptable behavior to security@sacredvote.org.

## License

By contributing to plausiden-zktls, you agree that your contributions will be licensed under the Apache License, Version 2.0.
