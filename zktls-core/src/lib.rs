//! # zktls-core
//!
//! Core types for zkTLS identity verification.
//!
//! This crate defines the foundational data structures used across the zkTLS toolkit:
//!
//! - **TLS session proofs** — cryptographic evidence that a TLS session occurred between
//!   a client and a specific server, co-signed by a notary.
//! - **Attestation formats** — structured claims extracted from TLS session data,
//!   such as "this government site confirmed the user is a registered voter."
//! - **Selective disclosure** — mechanisms for revealing only specific fields from
//!   a TLS response while keeping the rest hidden, preserving privacy.
//!
//! All types are serializable and designed for transport across network boundaries.
//! No cryptographic operations are performed here; this crate is purely structural.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use thiserror::Error;

/// Errors that can occur when working with core zkTLS types.
#[derive(Debug, Error)]
pub enum CoreError {
    /// The proof data failed structural validation.
    #[error("invalid proof structure: {0}")]
    InvalidProof(String),

    /// A required field was missing from the attestation.
    #[error("missing required field: {0}")]
    MissingField(String),

    /// The selective disclosure mask references fields that do not exist.
    #[error("disclosure mask references unknown field: {0}")]
    UnknownField(String),

    /// Serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// A cryptographic proof that a TLS session occurred between a client and server,
/// co-signed by a trusted notary.
///
/// The session proof contains the server's identity (hostname + certificate hash),
/// a commitment to the full TLS transcript, the notary's signature over that
/// commitment, and a timestamp. It does NOT contain the plaintext data itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionProof {
    /// The server hostname that was connected to (e.g., "votesearch.utah.gov").
    pub server_hostname: String,

    /// SHA-512 hash of the server's TLS certificate chain.
    pub certificate_hash: Vec<u8>,

    /// Commitment to the full TLS transcript (request + response).
    /// This is a Merkle root over the transcript chunks, allowing
    /// selective disclosure of individual chunks later.
    pub transcript_commitment: Vec<u8>,

    /// The notary's signature over the commitment and metadata.
    pub notary_signature: Vec<u8>,

    /// Public key of the notary that co-signed this session.
    pub notary_public_key: Vec<u8>,

    /// When the TLS session was established.
    pub session_timestamp: DateTime<Utc>,

    /// When the proof was generated (may differ from session time).
    pub proof_timestamp: DateTime<Utc>,
}

/// A structured claim extracted from a TLS session, with selective disclosure
/// applied so that only the claimed fields are visible.
///
/// For example, a voter registration check might produce an attestation with:
/// - `claim_type`: "voter_registration"
/// - `disclosed_fields`: {"state": "Utah", "status": "active"}
/// - `redacted_field_hashes`: hashes of name, address, DOB, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Unique identifier for this attestation.
    pub id: String,

    /// The type of claim being attested (e.g., "voter_registration", "age_verification").
    pub claim_type: String,

    /// Reference to the session proof that backs this attestation.
    pub session_proof_id: String,

    /// Fields that the user chose to disclose, as key-value pairs.
    pub disclosed_fields: std::collections::HashMap<String, serde_json::Value>,

    /// SHA-512 hashes of fields that were redacted. The verifier can confirm
    /// these fields existed in the original response without seeing their values.
    pub redacted_field_hashes: Vec<Vec<u8>>,

    /// The template that was used to extract and validate this attestation.
    pub template_id: String,

    /// When this attestation was created.
    pub created_at: DateTime<Utc>,

    /// Optional expiration time for the attestation.
    pub expires_at: Option<DateTime<Utc>>,
}

/// A mask that specifies which fields from a TLS response should be disclosed
/// and which should be redacted (replaced with their hashes).
///
/// The prover applies this mask before sharing the attestation with a verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureMask {
    /// Fields to reveal in plaintext. Each string is a dot-separated path
    /// into the response JSON (e.g., "voter.status", "voter.state").
    pub disclosed_paths: Vec<String>,

    /// Fields to redact. Their SHA-512 hashes will be included instead.
    pub redacted_paths: Vec<String>,
}

/// Compute the SHA-512 hash of a byte slice.
///
/// Used throughout the toolkit for transcript commitments, field hashing,
/// and certificate fingerprinting.
///
/// # Examples
///
/// ```
/// let hash = zktls_core::sha512_hash(b"hello world");
/// assert_eq!(hash.len(), 64); // SHA-512 produces 64 bytes
/// ```
pub fn sha512_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha512_hash_produces_64_bytes() {
        let hash = sha512_hash(b"test input");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn sha512_hash_is_deterministic() {
        let hash1 = sha512_hash(b"deterministic");
        let hash2 = sha512_hash(b"deterministic");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn sha512_hash_differs_for_different_inputs() {
        let hash1 = sha512_hash(b"input one");
        let hash2 = sha512_hash(b"input two");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn session_proof_serializes_roundtrip() {
        let proof = SessionProof {
            server_hostname: "votesearch.utah.gov".to_string(),
            certificate_hash: sha512_hash(b"cert"),
            transcript_commitment: sha512_hash(b"transcript"),
            notary_signature: vec![0u8; 64],
            notary_public_key: vec![0u8; 32],
            session_timestamp: Utc::now(),
            proof_timestamp: Utc::now(),
        };

        let json = serde_json::to_string(&proof).expect("serialization should succeed");
        let decoded: SessionProof =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(decoded.server_hostname, "votesearch.utah.gov");
    }

    #[test]
    fn attestation_serializes_roundtrip() {
        let mut disclosed = std::collections::HashMap::new();
        disclosed.insert(
            "state".to_string(),
            serde_json::Value::String("Utah".to_string()),
        );

        let attestation = Attestation {
            id: "att-001".to_string(),
            claim_type: "voter_registration".to_string(),
            session_proof_id: "proof-001".to_string(),
            disclosed_fields: disclosed,
            redacted_field_hashes: vec![sha512_hash(b"name"), sha512_hash(b"address")],
            template_id: "utah-voter-v1".to_string(),
            created_at: Utc::now(),
            expires_at: None,
        };

        let json = serde_json::to_string(&attestation).expect("serialization should succeed");
        let decoded: Attestation =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(decoded.claim_type, "voter_registration");
        assert_eq!(decoded.redacted_field_hashes.len(), 2);
    }

    #[test]
    fn disclosure_mask_serializes_roundtrip() {
        let mask = DisclosureMask {
            disclosed_paths: vec!["voter.status".to_string(), "voter.state".to_string()],
            redacted_paths: vec![
                "voter.name".to_string(),
                "voter.address".to_string(),
                "voter.dob".to_string(),
            ],
        };

        let json = serde_json::to_string(&mask).expect("serialization should succeed");
        let decoded: DisclosureMask =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(decoded.disclosed_paths.len(), 2);
        assert_eq!(decoded.redacted_paths.len(), 3);
    }
}
