# sacredvote-zktls

[![CI](https://github.com/PlausiDen/sacredvote-zktls/actions/workflows/ci.yml/badge.svg)](https://github.com/PlausiDen/sacredvote-zktls/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Prove who you are without revealing who you are. sacredvote-zktls is a toolkit that lets people verify real-world identity claims -- like voter registration status -- using cryptographic proofs from TLS sessions, without exposing any personal data to the verifier. It turns the trust model of identity verification inside out: instead of handing your information to a central authority and hoping they protect it, you prove your claim mathematically and keep your data to yourself.

## The Problem

Current identity verification systems require you to trust a central authority with your personal data. When a voting platform needs to confirm you are a registered voter, the conventional approach is to query a government database directly, creating a surveillance link between your identity and your ballot. Even "privacy-preserving" approaches typically involve a trusted intermediary that sees everything. This is a civil rights problem: the act of verifying your eligibility should not create a record that can be used to track how you vote, or that you voted at all.

Journalists verifying sources, activists confirming credentials, and ordinary voters participating in democracy all face the same dilemma: prove a claim about yourself, or maintain your privacy. You should not have to choose.

## How It Works

zkTLS (zero-knowledge TLS) uses a cryptographic notary to co-sign a TLS session between your browser and a target website. The notary attests that the session really happened and that the server's response is authentic, without needing to see the full plaintext. You then apply selective disclosure to reveal only the specific fields needed (e.g., "registration status: active") while cryptographically redacting everything else (name, address, date of birth).

```text
  You                       Notary                    Government Site
   |                          |                              |
   |-- start notarization --->|                              |
   |                          |                              |
   |<========= co-signed TLS handshake ===================>|
   |                          |                              |
   |-- "am I registered?" --->|------- forward request ----->|
   |                          |                              |
   |<-- attested response ----|<------ response -------------|
   |                          |                              |
   |== apply disclosure mask ==|                              |
   |   (reveal: status=Active) |                              |
   |   (redact: name, address) |                              |
   |                          |                              |
   |-- submit proof to ------>  Verifier                     |
   |   voting platform        |                              |
   |                          |                              |
   |   Verifier checks:                                      |
   |   1. Notary signature valid                             |
   |   2. Template matches expected format                   |
   |   3. Disclosed fields pass validation                   |
   |   Result: "voter is registered" (nothing else learned)  |
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
git clone https://github.com/PlausiDen/sacredvote-zktls.git
cd sacredvote-zktls

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
sacredvote-zktls/
  zktls-core/         Core types: session proofs, attestations, disclosure masks
  zktls-notary/       Notary service for co-signing TLS sessions
  zktls-verifier/     Proof verification against templates and trust stores
  zktls-templates/    Template definitions for specific verification targets
```

## The PlausiDen Ecosystem

sacredvote-zktls is part of the [Sacred.Vote](https://sacred.vote) civic technology platform, which provides zero-trust cryptographic polling where voter identity is mathematically decoupled from ballot records. While built for Sacred.Vote's voter verification flow, this toolkit is a standalone public good: any application that needs to verify real-world identity claims without centralized data collection can use it.

Related repositories:
- [Sacred.Vote](https://github.com/PlausiDen/Sacred.Vote) -- The voting platform
- [sacredvote-gatekeeper](https://github.com/PlausiDen/sacredvote-gatekeeper) -- Access control and session management
- [plausiden-crdt](https://github.com/PlausiDen/plausiden-crdt) -- Conflict-free replicated data types

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
