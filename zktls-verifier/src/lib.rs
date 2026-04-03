//! # zktls-verifier
//!
//! Verifies zkTLS proofs against templates and checks notary signatures.
//!
//! The verifier is the component that a relying party (e.g., Sacred.Vote's ballot
//! server) uses to confirm that an identity claim is backed by a valid zkTLS proof.
//! Verification involves three checks:
//!
//! 1. **Notary signature** — the proof was co-signed by a trusted notary, confirming
//!    the TLS session actually happened with the claimed server.
//! 2. **Template match** — the disclosed fields match the expected format defined
//!    by a verification template (e.g., "Utah voter registration returns a JSON
//!    object with a `status` field").
//! 3. **Disclosure integrity** — the disclosed and redacted fields together
//!    reconstruct the original transcript commitment (Merkle root verification).
//!
//! The verifier never sees redacted data. It only confirms that the disclosed
//! fields are consistent with the proof and that the proof is properly signed.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zktls_core::{Attestation, SessionProof};

/// Errors that can occur during proof verification.
#[derive(Debug, Error)]
pub enum VerificationError {
    /// The notary's signature did not verify against the proof data.
    #[error("notary signature verification failed")]
    InvalidSignature,

    /// The notary that signed this proof is not in the trusted set.
    #[error("notary not trusted: {0}")]
    UntrustedNotary(String),

    /// The attestation does not match the expected template.
    #[error("template mismatch: {0}")]
    TemplateMismatch(String),

    /// The disclosed fields do not reconstruct the transcript commitment.
    #[error("disclosure integrity check failed")]
    DisclosureIntegrityFailed,

    /// The attestation has expired.
    #[error("attestation expired at {0}")]
    Expired(String),

    /// A required disclosed field is missing.
    #[error("required field missing: {0}")]
    MissingRequiredField(String),

    /// A disclosed field value does not match the expected pattern.
    #[error("field '{field}' value '{value}' does not match pattern '{pattern}'")]
    FieldPatternMismatch {
        /// The field name that failed validation.
        field: String,
        /// The actual value found.
        value: String,
        /// The expected regex pattern.
        pattern: String,
    },
}

/// The result of a successful verification, containing extracted claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the proof passed all verification checks.
    pub valid: bool,

    /// The claim type that was verified (e.g., "voter_registration").
    pub claim_type: String,

    /// The verified disclosed fields (only those that passed template validation).
    pub verified_fields: std::collections::HashMap<String, serde_json::Value>,

    /// The notary public key that signed the proof.
    pub notary_key: Vec<u8>,

    /// Human-readable summary of what was verified.
    pub summary: String,
}

/// A trusted notary entry in the verifier's trust store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedNotary {
    /// Human-readable name for this notary.
    pub name: String,

    /// The notary's public key.
    pub public_key: Vec<u8>,

    /// Optional URL where the notary's service is hosted.
    pub endpoint: Option<String>,
}

/// Trait for proof verification implementations.
///
/// Different verification strategies may check different subsets of conditions
/// or use different signature schemes. This trait abstracts over those choices.
pub trait Verify {
    /// Verify a session proof against the trust store.
    ///
    /// Checks the notary signature and confirms the notary is trusted.
    fn verify_proof(&self, proof: &SessionProof) -> Result<(), VerificationError>;

    /// Verify an attestation against a template and its backing proof.
    ///
    /// This is the primary verification entry point. It checks the proof,
    /// matches the attestation against the template, and validates all
    /// disclosed field values.
    fn verify_attestation(
        &self,
        attestation: &Attestation,
        proof: &SessionProof,
    ) -> Result<VerificationResult, VerificationError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_result_serializes_roundtrip() {
        let mut fields = std::collections::HashMap::new();
        fields.insert(
            "state".to_string(),
            serde_json::Value::String("Utah".to_string()),
        );
        fields.insert(
            "status".to_string(),
            serde_json::Value::String("active".to_string()),
        );

        let result = VerificationResult {
            valid: true,
            claim_type: "voter_registration".to_string(),
            verified_fields: fields,
            notary_key: vec![0u8; 32],
            summary: "Voter registration confirmed for state: Utah".to_string(),
        };

        let json = serde_json::to_string(&result).expect("serialization should succeed");
        let decoded: VerificationResult =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert!(decoded.valid);
        assert_eq!(decoded.claim_type, "voter_registration");
        assert_eq!(decoded.verified_fields.len(), 2);
    }

    #[test]
    fn trusted_notary_serializes_roundtrip() {
        let notary = TrustedNotary {
            name: "PlausiDen Notary Alpha".to_string(),
            public_key: vec![1u8; 32],
            endpoint: Some("https://notary.sacredvote.org".to_string()),
        };

        let json = serde_json::to_string(&notary).expect("serialization should succeed");
        let decoded: TrustedNotary =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(decoded.name, "PlausiDen Notary Alpha");
        assert!(decoded.endpoint.is_some());
    }
}
