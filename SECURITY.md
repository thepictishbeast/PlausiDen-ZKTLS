# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in plausiden-zktls, please report it responsibly.

**Email:** security@sacredvote.org

Please include:
- A description of the vulnerability
- Steps to reproduce
- The potential impact
- Any suggested fixes (optional)

**Do not** open a public GitHub issue for security vulnerabilities.

## Response Time

- **Acknowledgment:** within 48 hours of receiving the report
- **Initial assessment:** within 7 days
- **Fix or mitigation:** within 30 days for critical issues, 90 days for others

## Scope

This security policy covers:
- All code in this repository (zktls-core, zktls-notary, zktls-verifier, zktls-templates)
- The cryptographic protocols described in ARCHITECTURE.md
- Template definitions that could lead to unintended data disclosure

Out of scope:
- Vulnerabilities in upstream dependencies (report those to the dependency maintainers, but do let us know so we can update)
- Issues in deployment configurations not provided by this repository
- Social engineering attacks

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Design Principles

This project handles sensitive identity data. All contributions must follow these principles:

- **No secret material in logs or debug output.** The `tracing` crate is used for logging; ensure no PII or cryptographic keys appear at any log level.
- **Audited cryptographic crates only.** Use `ring`, `ed25519-dalek`, `sha2`, `chacha20poly1305`, or other well-established crates. No custom cryptography.
- **Zeroize secrets after use.** Any key material held in memory must implement `Zeroize` and be dropped explicitly when no longer needed.
- **Validate all inputs.** Template field patterns, JSON paths, hostnames -- all must be validated before use.
