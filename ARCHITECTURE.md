# Architecture

## System Diagram

```text
+------------------+      +------------------+      +------------------+
|                  |      |                  |      |                  |
|   User Agent     |<---->|   Notary         |<---->|  Target Server   |
|   (browser/CLI)  |      |   (zktls-notary) |      |  (govt site)     |
|                  |      |                  |      |                  |
+--------+---------+      +--------+---------+      +------------------+
         |                         |
         |  SessionProof           |
         v                         |
+--------+---------+               |
|                  |               |
|   Prover         |               |
|   (client-side)  |               |
|                  |               |
+--------+---------+               |
         |                         |
         |  Attestation            |
         |  (selective disclosure) |
         v                         |
+--------+---------+      +--------+---------+
|                  |      |                  |
|   Verifier       |<---->|  Template        |
|  (zktls-verifier)|      |  Registry        |
|                  |      | (zktls-templates)|
+--------+---------+      +------------------+
         |
         |  VerificationResult
         v
+--------+---------+
|                  |
|  Relying Party   |
|  (Sacred.Vote)   |
|                  |
+------------------+
```

## Components

### zktls-core

The foundational crate containing type definitions shared across all other crates. No business logic, no I/O, no cryptographic operations -- purely structural types with serialization support.

Key types:
- `SessionProof` -- cryptographic proof of a TLS session
- `Attestation` -- a structured claim with selective disclosure applied
- `DisclosureMask` -- specifies which response fields to reveal vs. redact

### zktls-notary

The notary service that co-signs TLS sessions. Runs as a standalone network service. The notary participates in a multi-party computation (MPC) TLS handshake: the client and notary together hold the TLS session key, so neither party alone can fabricate a transcript.

Responsibilities:
- Accept notarization requests from clients
- Participate in the MPC-TLS handshake with the target server
- Generate transcript commitments (Merkle tree over response chunks)
- Sign the commitment with the notary's key
- Enforce hostname allowlists and rate limits

### zktls-verifier

The verification engine used by relying parties. Given an attestation and its backing session proof, the verifier checks:

1. The notary signature is valid and from a trusted notary
2. The attestation's disclosed fields match the template's expected format
3. The disclosed + redacted field hashes reconstruct the transcript commitment
4. Field values pass the template's validation patterns
5. The attestation has not expired

### zktls-templates

Template definitions that describe specific verification targets. Each template encodes knowledge about a particular website's API: what endpoint to hit, what the response looks like, and which fields can be extracted.

Templates are versioned. When a government site changes its API, a new template version is published. Old proofs remain valid against the template version they were generated with.

## Data Flow

### Proof Generation

1. User opens the target verification site (e.g., Utah voter registration lookup).
2. Client initiates a notarization session with a trusted notary.
3. Client and notary perform a three-party MPC-TLS handshake with the target server.
4. Client sends the verification request through the notarized channel.
5. Target server responds; the response is committed into a Merkle tree.
6. Notary signs the transcript commitment, producing a `SessionProof`.
7. Client applies a `DisclosureMask` (from the template) to produce an `Attestation`.
8. Client submits the `Attestation` + `SessionProof` to the relying party.

### Proof Verification

1. Relying party receives `Attestation` + `SessionProof`.
2. Verifier loads the matching `VerificationTemplate` from the registry.
3. Verifier checks the notary signature against its trust store.
4. Verifier validates disclosed fields against the template's field definitions.
5. Verifier confirms the Merkle root reconstructs from disclosed + redacted hashes.
6. If all checks pass, verifier returns a `VerificationResult` with the confirmed claims.

## Threat Model

### What This System Defends Against

- **Relying party surveillance:** The verifier learns only the disclosed claim (e.g., "voter is registered") and nothing else. No name, address, or browsing history leaks to the voting platform.
- **Proof fabrication:** A user cannot forge a proof without actually visiting the target server. The notary's co-signature prevents this.
- **Replay attacks:** Attestations carry timestamps and can be scoped to a single verification session. Template-level expiration prevents reuse.
- **Template manipulation:** Templates are versioned and integrity-checked. A malicious template cannot extract fields that do not exist in the server's response.

### What Is Out of Scope

- **Compromised notary:** If the notary colludes with the prover, they can fabricate proofs. Mitigation: use multiple independent notaries, or a decentralized notary network.
- **Compromised target server:** If the government site returns false data, the proof will reflect that false data. zkTLS proves the server said something, not that the server was truthful.
- **Client-side malware:** If the user's device is compromised, the attacker can see the full plaintext response before disclosure is applied. This is inherent to any client-side system.
- **Traffic analysis:** An observer can see that the user connected to both the notary and the target server. Timing correlation is possible. Mitigation is out of scope (use Tor or a VPN).

## Key Design Decisions

### Merkle Tree Transcript Commitment

The TLS response is chunked and organized into a Merkle tree. This allows selective disclosure at the chunk level: individual fields can be revealed while others remain as hashes. The Merkle root serves as the commitment that the notary signs.

**Rationale:** A single hash of the entire response would be all-or-nothing. A Merkle structure gives fine-grained disclosure with efficient proofs.

### Template-Based Extraction

Rather than general-purpose response parsing, we use pre-defined templates for each verification target.

**Rationale:** Templates can be audited, versioned, and distributed. They constrain what the system can do, which is a feature: a template for voter registration cannot accidentally disclose medical records. The closed set of templates is easier to reason about for security.

### Separated Crates

The workspace is split into four crates with minimal coupling.

**Rationale:** The notary runs on a server, the verifier runs on the relying party's server, the templates may be distributed as a data package, and the core types are shared by all. Separating them allows each to be deployed, audited, and versioned independently.

## Future Directions

- **Decentralized notary network:** Replace the single trusted notary with a threshold signature scheme across multiple independent notaries.
- **Browser extension integration:** Package the client-side notarization flow as a browser extension for seamless use.
- **Formal verification:** Use Lean 4 to prove properties of the Merkle commitment scheme and the selective disclosure protocol.
- **Post-quantum signatures:** Migrate notary signatures to lattice-based schemes when standards stabilize.
- **Additional templates:** Expand beyond voter registration to age verification, professional licensing, academic credentials, and more.
