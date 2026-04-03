# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial workspace scaffold with four crates: zktls-core, zktls-notary, zktls-verifier, zktls-templates.
- Core types: `SessionProof`, `Attestation`, `DisclosureMask` in zktls-core.
- Notary types: `NotaryConfig`, `NotarySession`, `SessionState`, `Notarize` trait in zktls-notary.
- Verifier types: `VerificationResult`, `TrustedNotary`, `Verify` trait in zktls-verifier.
- Template types: `VerificationTemplate`, `TargetServer`, `FieldDefinition`, `TemplateRegistry` in zktls-templates.
- SHA-512 utility function in zktls-core.
- Full test suite for all crate types.
- CI pipeline with fmt, clippy, test, build, and audit.
- Repository documentation: README, ARCHITECTURE, CONTRIBUTING, SECURITY, CHANGELOG.
