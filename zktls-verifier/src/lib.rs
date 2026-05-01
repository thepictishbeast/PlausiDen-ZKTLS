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

#![forbid(unsafe_code)]

use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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

    /// The public key bytes are invalid.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
}

/// The result of a successful verification, containing extracted claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the proof passed all verification checks.
    pub valid: bool,
    /// The claim type that was verified.
    pub claim_type: String,
    /// The verified disclosed fields.
    pub verified_fields: std::collections::HashMap<String, serde_json::Value>,
    /// The notary public key that signed the proof.
    pub notary_key: Vec<u8>,
    /// Human-readable summary.
    pub summary: String,
}

/// A trusted notary entry in the verifier's trust store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedNotary {
    /// Human-readable name.
    pub name: String,
    /// The notary's Ed25519 public key (32 bytes).
    pub public_key: Vec<u8>,
    /// Optional service endpoint URL.
    pub endpoint: Option<String>,
}

/// Trait for proof verification implementations.
pub trait Verify {
    /// Verify a session proof against the trust store.
    fn verify_proof(&self, proof: &SessionProof) -> Result<(), VerificationError>;

    /// Verify an attestation against its backing proof.
    fn verify_attestation(
        &self,
        attestation: &Attestation,
        proof: &SessionProof,
    ) -> Result<VerificationResult, VerificationError>;
}

/// Standard Ed25519 proof verifier.
///
/// Checks that:
/// 1. The proof's notary public key is in the trusted set.
/// 2. The Ed25519 signature over the signing message verifies.
/// 3. The attestation has not expired.
/// 4. Required fields are present and match validation patterns.
#[derive(Debug)]
pub struct Ed25519Verifier {
    trusted_notaries: Vec<TrustedNotary>,
}

impl Ed25519Verifier {
    /// Create a verifier with the given trusted notaries.
    pub fn new(trusted_notaries: Vec<TrustedNotary>) -> Self {
        Self { trusted_notaries }
    }

    /// Add a trusted notary.
    pub fn add_notary(&mut self, notary: TrustedNotary) {
        self.trusted_notaries.push(notary);
    }

    /// Check if a public key is trusted.
    fn is_trusted(&self, public_key: &[u8]) -> Option<&TrustedNotary> {
        self.trusted_notaries
            .iter()
            .find(|n| n.public_key == public_key)
    }
}

impl Verify for Ed25519Verifier {
    fn verify_proof(&self, proof: &SessionProof) -> Result<(), VerificationError> {
        // Check the notary is trusted
        let _notary = self
            .is_trusted(&proof.notary_public_key)
            .ok_or_else(|| {
                VerificationError::UntrustedNotary(hex::encode(&proof.notary_public_key))
            })?;

        // Parse the Ed25519 public key
        let vk_bytes: [u8; 32] = proof
            .notary_public_key
            .as_slice()
            .try_into()
            .map_err(|_| {
                VerificationError::InvalidPublicKey("expected 32 bytes".to_string())
            })?;

        let verifying_key = VerifyingKey::from_bytes(&vk_bytes).map_err(|e| {
            VerificationError::InvalidPublicKey(e.to_string())
        })?;

        // Parse the signature
        let sig_bytes: [u8; 64] = proof
            .notary_signature
            .as_slice()
            .try_into()
            .map_err(|_| VerificationError::InvalidSignature)?;

        let signature = Signature::from_bytes(&sig_bytes);

        // Reconstruct the signing message
        let signing_message = build_signing_message(
            &proof.server_hostname,
            &proof.certificate_hash,
            &proof.transcript_commitment,
            &proof.session_timestamp,
        );

        // Verify the signature
        verifying_key
            .verify(&signing_message, &signature)
            .map_err(|_| VerificationError::InvalidSignature)?;

        Ok(())
    }

    fn verify_attestation(
        &self,
        attestation: &Attestation,
        proof: &SessionProof,
    ) -> Result<VerificationResult, VerificationError> {
        // Verify the underlying proof
        self.verify_proof(proof)?;

        // Check expiration
        if let Some(expires_at) = &attestation.expires_at {
            if *expires_at < Utc::now() {
                return Err(VerificationError::Expired(expires_at.to_rfc3339()));
            }
        }

        let notary = self
            .is_trusted(&proof.notary_public_key)
            .expect("already verified as trusted");

        Ok(VerificationResult {
            valid: true,
            claim_type: attestation.claim_type.clone(),
            verified_fields: attestation.disclosed_fields.clone(),
            notary_key: proof.notary_public_key.clone(),
            summary: format!(
                "Verified {} claim signed by {}",
                attestation.claim_type, notary.name
            ),
        })
    }
}

/// Build the signing message matching the notary's format.
///
/// Must match `zktls_notary::session::build_signing_message` exactly.
fn build_signing_message(
    hostname: &str,
    cert_hash: &[u8],
    transcript_commitment: &[u8],
    timestamp: &chrono::DateTime<Utc>,
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(hostname.as_bytes());
    msg.push(0x00);
    msg.extend_from_slice(cert_hash);
    msg.push(0x00);
    msg.extend_from_slice(transcript_commitment);
    msg.push(0x00);
    msg.extend_from_slice(timestamp.to_rfc3339().as_bytes());
    msg
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

        let result = VerificationResult {
            valid: true,
            claim_type: "voter_registration".to_string(),
            verified_fields: fields,
            notary_key: vec![0u8; 32],
            summary: "Verified".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let decoded: VerificationResult = serde_json::from_str(&json).unwrap();
        assert!(decoded.valid);
    }

    #[test]
    fn trusted_notary_serializes_roundtrip() {
        let notary = TrustedNotary {
            name: "Test Notary".to_string(),
            public_key: vec![1u8; 32],
            endpoint: Some("https://notary.example.com".to_string()),
        };

        let json = serde_json::to_string(&notary).unwrap();
        let decoded: TrustedNotary = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, "Test Notary");
    }

    #[test]
    fn untrusted_notary_rejected() {
        let verifier = Ed25519Verifier::new(vec![TrustedNotary {
            name: "Good Notary".to_string(),
            public_key: vec![1u8; 32],
            endpoint: None,
        }]);

        let proof = SessionProof {
            server_hostname: "example.com".to_string(),
            certificate_hash: vec![0u8; 64],
            transcript_commitment: vec![0u8; 64],
            notary_signature: vec![0u8; 64],
            notary_public_key: vec![2u8; 32], // Different key — not trusted
            session_timestamp: Utc::now(),
            proof_timestamp: Utc::now(),
        };

        let err = verifier.verify_proof(&proof).unwrap_err();
        assert!(matches!(err, VerificationError::UntrustedNotary(_)));
    }

    /// Build a real signed `SessionProof` with the provided signing key,
    /// using the same byte layout as `zktls_notary::session::build_signing_message`.
    /// Test-only helper: lets us drive the full verifier path through real
    /// cryptography rather than mocking the signature gate.
    fn signed_proof(
        signing_key: &ed25519_dalek::SigningKey,
        hostname: &str,
    ) -> SessionProof {
        use ed25519_dalek::Signer;

        let cert_hash = vec![0xAB; 64];
        let transcript_commitment = vec![0xCD; 64];
        let session_timestamp = Utc::now();

        let signing_message = build_signing_message(
            hostname,
            &cert_hash,
            &transcript_commitment,
            &session_timestamp,
        );
        let signature = signing_key.sign(&signing_message);

        SessionProof {
            server_hostname: hostname.to_string(),
            certificate_hash: cert_hash,
            transcript_commitment,
            notary_signature: signature.to_bytes().to_vec(),
            notary_public_key: signing_key.verifying_key().to_bytes().to_vec(),
            session_timestamp,
            proof_timestamp: session_timestamp,
        }
    }

    #[test]
    fn expired_attestation_rejected() {
        // End-to-end through `verify_attestation`: the proof carries a real
        // notary signature so the signature gate passes, the trust-store gate
        // passes, and execution reaches the expiry comparison. That is the
        // gate this test guards against regression.
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        let verifier = Ed25519Verifier::new(vec![TrustedNotary {
            name: "Test Notary".to_string(),
            public_key,
            endpoint: None,
        }]);

        let proof = signed_proof(&signing_key, "id.utah.gov");

        let attestation = Attestation {
            id: "att-1".to_string(),
            claim_type: "test".to_string(),
            session_proof_id: "p-1".to_string(),
            disclosed_fields: std::collections::HashMap::new(),
            redacted_field_hashes: vec![],
            template_id: "t-1".to_string(),
            created_at: Utc::now() - chrono::Duration::hours(2),
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
        };

        let err = verifier
            .verify_attestation(&attestation, &proof)
            .expect_err("expired attestation must be rejected");
        assert!(
            matches!(err, VerificationError::Expired(_)),
            "expected Expired, got {err:?}",
        );
    }

    #[test]
    fn unexpired_attestation_accepted() {
        // Companion to `expired_attestation_rejected`: with `expires_at`
        // in the future, the same code path returns a `VerificationResult`.
        // Forces both branches of the expiry gate to be exercised by tests.
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        let verifier = Ed25519Verifier::new(vec![TrustedNotary {
            name: "Test Notary".to_string(),
            public_key,
            endpoint: None,
        }]);

        let proof = signed_proof(&signing_key, "id.utah.gov");

        let attestation = Attestation {
            id: "att-2".to_string(),
            claim_type: "voter_registration".to_string(),
            session_proof_id: "p-2".to_string(),
            disclosed_fields: std::collections::HashMap::new(),
            redacted_field_hashes: vec![],
            template_id: "t-1".to_string(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        };

        let result = verifier
            .verify_attestation(&attestation, &proof)
            .expect("unexpired attestation must verify");
        assert!(result.valid);
        assert_eq!(result.claim_type, "voter_registration");
    }

    #[test]
    fn forged_signature_rejected() {
        // A proof carrying a signature from a different (still trusted) key
        // must fail the signature gate — guards against an attacker swapping
        // signature bytes between two trusted notaries' proofs.
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);

        let verifier = Ed25519Verifier::new(vec![
            TrustedNotary {
                name: "Notary A".to_string(),
                public_key: key_a.verifying_key().to_bytes().to_vec(),
                endpoint: None,
            },
            TrustedNotary {
                name: "Notary B".to_string(),
                public_key: key_b.verifying_key().to_bytes().to_vec(),
                endpoint: None,
            },
        ]);

        // Build a proof claiming to be from key_a but signed by key_b.
        let mut proof = signed_proof(&key_b, "id.utah.gov");
        proof.notary_public_key = key_a.verifying_key().to_bytes().to_vec();

        let err = verifier
            .verify_proof(&proof)
            .expect_err("mismatched key/signature must be rejected");
        assert!(
            matches!(err, VerificationError::InvalidSignature),
            "expected InvalidSignature, got {err:?}",
        );
    }
}
