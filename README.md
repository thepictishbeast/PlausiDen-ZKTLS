# plausiden-zktls

[![CI](https://github.com/thepictishbeast/plausiden-zktls/actions/workflows/ci.yml/badge.svg)](https://github.com/thepictishbeast/plausiden-zktls/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Prove who you are without revealing who you are. plausiden-zktls is a general-purpose toolkit that lets applications verify real-world identity claims -- like voter registration, age, professional credentials, or academic records -- using cryptographic proofs from TLS sessions, without exposing any personal data to the verifier. It turns the trust model of identity verification inside out: instead of handing your information to a central authority and hoping they protect it, you prove your claim mathematically and keep your data to yourself.

## The Problem

Current identity verification systems require you to trust a central authority with your personal data. When any application needs to confirm a real-world claim about a person, the conventional approach is to query a database directly, creating a surveillance link between the person's identity and the service they are using. Even "privacy-preserving" approaches typically involve a trusted intermediary that sees everything. This is a civil rights problem: the act of verifying a claim should not create a record that can be used for tracking or surveillance.

Journalists verifying sources, activists confirming credentials, voters participating in democracy, and ordinary people proving their age or qualifications all face the same dilemma: prove a claim about yourself, or maintain your privacy. You should not have to choose.

## How It Works

zkTLS (zero-knowledge TLS) uses a cryptographic notary to co-sign a TLS session between the user's browser and a target website. The notary attests that the session really happened and that the server's response is authentic, without needing to see the full plaintext. The user then applies selective disclosure to reveal only the specific fields needed (e.g., "registration status: active") while cryptographically redacting everything else (name, address, date of birth).

```text
  User                      Notary                    Target Site
   |                          |                              |
   |-- start notarization --->|                              |
   |                          |                              |
   |<========= co-signed TLS handshake ===================>|
   |                          |                              |
   |-- "verify my claim" ---->|------- forward request ----->|
   |                          |                              |
   |<-- attested response ----|<------ response -------------|
   |                          |                              |
   |== apply disclosure mask ==|                              |
   |   (reveal: claim=valid)   |                              |
   |   (redact: name, address) |                              |
   |                          |                              |
   |-- submit proof to ------>  Verifier                     |
   |   relying party          |                              |
   |                          |                              |
   |   Verifier checks:                                      |
   |   1. Notary signature valid                             |
   |   2. Template matches expected format                   |
   |   3. Disclosed fields pass validation                   |
   |   Result: "claim is valid" (nothing else learned)       |
```

The verifier learns exactly one fact -- the claim is valid -- and nothing more.

## Current Status

| Component | Crate | Status |
|-----------|-------|--------|
| Core types | `zktls-core` | In progress |
| Notary service | `zktls-notary` | Planned |
| Proof verifier | `zktls-verifier` | Planned |
| Verification templates | `zktls-templates` | Planned |

## Quick Start

```bash
# Clone the repository
git clone https://github.com/thepictishbeast/plausiden-zktls.git
cd plausiden-zktls

# Build the workspace
cargo build

# Run all tests
cargo test

# Or use Just (recommended)
just check-all
```

Requires Rust 1.75+ and [Just](https://github.com/casey/just) for the command runner.

## Workspace Structure

```
plausiden-zktls/
  zktls-core/         Core types: session proofs, attestations, disclosure masks
  zktls-notary/       Notary service for co-signing TLS sessions
  zktls-verifier/     Proof verification against templates and trust stores
  zktls-templates/    Template definitions for specific verification targets
```

## The PlausiDen Ecosystem

plausiden-zktls is a standalone general-purpose library in the [PlausiDen](https://github.com/PlausiDen) ecosystem. It is used by [sacredvote-zktls](https://github.com/thepictishbeast/sacredvote-zktls) to power voter registration verification on the [Sacred.Vote](https://sacred.vote) civic technology platform, but the toolkit itself is application-agnostic. Any project that needs to verify real-world identity claims without centralized data collection can use it: age verification, professional licensing, academic credentials, and more.

Related repositories:
- [sacredvote-zktls](https://github.com/thepictishbeast/sacredvote-zktls) -- Sacred.Vote voter verification integration
- [Sacred.Vote](https://github.com/thepictishbeast/Sacred.Vote) -- The voting platform
- [plausiden-crdt](https://github.com/thepictishbeast/plausiden-crdt) -- Conflict-free replicated data types

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
