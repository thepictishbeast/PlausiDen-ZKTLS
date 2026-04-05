//! Notary session management.
//!
//! Each notarization request creates a session that tracks the lifecycle
//! from initialization through fetch, commitment, and proof generation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use zktls_core::{Attestation, SessionProof};

use crate::error::NotaryError;
use crate::keys::NotaryKeyPair;

/// The lifecycle states of a notary session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session created, ready to fetch.
    Initialized,
    /// Fetching the target server.
    Fetching,
    /// Response received, generating commitment.
    Committing,
    /// Proof signed and ready.
    Completed,
    /// Session failed.
    Failed(String),
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionState::Initialized => write!(f, "initialized"),
            SessionState::Fetching => write!(f, "fetching"),
            SessionState::Committing => write!(f, "committing"),
            SessionState::Completed => write!(f, "completed"),
            SessionState::Failed(reason) => write!(f, "failed: {reason}"),
        }
    }
}

/// An active notarization session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotarySession {
    /// Unique session identifier.
    pub id: String,
    /// Target server hostname.
    pub target_hostname: String,
    /// Template ID used for this session.
    pub template_id: String,
    /// Current state.
    pub state: SessionState,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// The raw response body (cleared after proof generation).
    #[serde(skip)]
    pub response_body: Option<String>,
    /// The TLS certificate hash from the target server.
    pub certificate_hash: Option<Vec<u8>>,
    /// The generated session proof (set on completion).
    pub proof: Option<SessionProof>,
    /// The generated attestation (set on completion).
    pub attestation: Option<Attestation>,
}

/// Thread-safe session store.
#[derive(Debug, Clone)]
pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<String, NotarySession>>>,
    max_sessions: usize,
}

impl SessionStore {
    /// Create a new session store with the given capacity.
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            max_sessions,
        }
    }

    /// Create a new session. Returns the session ID.
    pub async fn create(
        &self,
        target_hostname: String,
        template_id: String,
    ) -> Result<String, NotaryError> {
        let mut sessions = self.sessions.write().await;

        // Evict completed/failed sessions if at capacity
        if sessions.len() >= self.max_sessions {
            let to_remove: Vec<String> = sessions
                .iter()
                .filter(|(_, s)| {
                    matches!(s.state, SessionState::Completed | SessionState::Failed(_))
                })
                .map(|(id, _)| id.clone())
                .collect();

            for id in &to_remove {
                sessions.remove(id);
            }

            if sessions.len() >= self.max_sessions {
                return Err(NotaryError::TooManySessions(self.max_sessions));
            }
        }

        let id = Uuid::new_v4().to_string();
        let session = NotarySession {
            id: id.clone(),
            target_hostname,
            template_id,
            state: SessionState::Initialized,
            created_at: Utc::now(),
            response_body: None,
            certificate_hash: None,
            proof: None,
            attestation: None,
        };

        sessions.insert(id.clone(), session);
        Ok(id)
    }

    /// Get a session by ID.
    pub async fn get(&self, id: &str) -> Result<NotarySession, NotaryError> {
        let sessions = self.sessions.read().await;
        sessions
            .get(id)
            .cloned()
            .ok_or_else(|| NotaryError::SessionNotFound(id.to_string()))
    }

    /// Update a session's state.
    pub async fn update_state(
        &self,
        id: &str,
        state: SessionState,
    ) -> Result<(), NotaryError> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| NotaryError::SessionNotFound(id.to_string()))?;
        session.state = state;
        Ok(())
    }

    /// Store the fetch result in a session.
    pub async fn store_response(
        &self,
        id: &str,
        body: String,
        cert_hash: Vec<u8>,
    ) -> Result<(), NotaryError> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| NotaryError::SessionNotFound(id.to_string()))?;
        session.response_body = Some(body);
        session.certificate_hash = Some(cert_hash);
        Ok(())
    }

    /// Store the completed proof and attestation, clear the raw response.
    pub async fn store_proof(
        &self,
        id: &str,
        proof: SessionProof,
        attestation: Attestation,
    ) -> Result<(), NotaryError> {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(id)
            .ok_or_else(|| NotaryError::SessionNotFound(id.to_string()))?;
        session.proof = Some(proof);
        session.attestation = Some(attestation);
        session.response_body = None; // Don't retain plaintext
        session.state = SessionState::Completed;
        Ok(())
    }

    /// Count active (non-completed, non-failed) sessions.
    pub async fn active_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions
            .values()
            .filter(|s| {
                !matches!(s.state, SessionState::Completed | SessionState::Failed(_))
            })
            .count()
    }
}

/// Build the proof signing message from session data.
///
/// The notary signs: hostname || cert_hash || transcript_commitment || timestamp.
/// This binds the proof to a specific server, response, and time.
pub fn build_signing_message(
    hostname: &str,
    cert_hash: &[u8],
    transcript_commitment: &[u8],
    timestamp: &DateTime<Utc>,
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(hostname.as_bytes());
    msg.push(0x00); // separator
    msg.extend_from_slice(cert_hash);
    msg.push(0x00);
    msg.extend_from_slice(transcript_commitment);
    msg.push(0x00);
    msg.extend_from_slice(timestamp.to_rfc3339().as_bytes());
    msg
}

/// Generate a session proof from a completed fetch.
///
/// Creates the transcript commitment (SHA-512 of the response body),
/// signs the proof with the notary's key, and assembles the SessionProof.
pub fn generate_proof(
    hostname: &str,
    response_body: &str,
    cert_hash: &[u8],
    keypair: &NotaryKeyPair,
) -> SessionProof {
    let now = Utc::now();
    let transcript_commitment = zktls_core::sha512_hash(response_body.as_bytes());

    let signing_message = build_signing_message(
        hostname,
        cert_hash,
        &transcript_commitment,
        &now,
    );

    let signature = keypair.sign(&signing_message);

    SessionProof {
        server_hostname: hostname.to_string(),
        certificate_hash: cert_hash.to_vec(),
        transcript_commitment,
        notary_signature: signature,
        notary_public_key: keypair.public_key_bytes(),
        session_timestamp: now,
        proof_timestamp: now,
    }
}

/// Disclosed fields + redacted hashes extracted from a response.
pub type ExtractedFields = (HashMap<String, serde_json::Value>, Vec<Vec<u8>>);

/// Extract fields from a JSON response body according to template field definitions.
///
/// Returns a map of field_name -> value for disclosed fields, and a vec of
/// SHA-512 hashes for redacted fields.
pub fn extract_fields(
    response_body: &str,
    fields: &[zktls_templates::FieldDefinition],
    disclosure: &zktls_core::DisclosureMask,
) -> Result<ExtractedFields, NotaryError> {
    let json: serde_json::Value = serde_json::from_str(response_body)
        .map_err(|e| NotaryError::ExtractionFailed(format!("invalid JSON: {e}")))?;

    let mut disclosed = HashMap::new();
    let mut redacted_hashes = Vec::new();

    for field in fields {
        // Navigate the dot-separated path
        let value = navigate_json_path(&json, &field.json_path);

        if disclosure.disclosed_paths.contains(&field.json_path) {
            // This field should be disclosed
            match value {
                Some(v) => {
                    disclosed.insert(field.name.clone(), v.clone());
                }
                None if field.required => {
                    return Err(NotaryError::ExtractionFailed(format!(
                        "required field '{}' not found at path '{}'",
                        field.name, field.json_path
                    )));
                }
                None => {
                    disclosed.insert(field.name.clone(), serde_json::Value::Null);
                }
            }
        } else if disclosure.redacted_paths.contains(&field.json_path) {
            // This field should be redacted — store its hash
            if let Some(v) = value {
                let hash_input = format!("{}:{}", field.json_path, v);
                redacted_hashes.push(zktls_core::sha512_hash(hash_input.as_bytes()));
            }
        }
    }

    Ok((disclosed, redacted_hashes))
}

/// Navigate a dot-separated JSON path (e.g., "voter.status") to find a value.
fn navigate_json_path<'a>(
    root: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zktls_core::DisclosureMask;
    use zktls_templates::{FieldDefinition, FieldType};

    #[tokio::test]
    async fn session_store_create_and_get() {
        let store = SessionStore::new(10);
        let id = store
            .create("example.com".to_string(), "test-v1".to_string())
            .await
            .unwrap();

        let session = store.get(&id).await.unwrap();
        assert_eq!(session.target_hostname, "example.com");
        assert_eq!(session.state, SessionState::Initialized);
    }

    #[tokio::test]
    async fn session_store_respects_capacity() {
        let store = SessionStore::new(2);
        store
            .create("a.com".to_string(), "t".to_string())
            .await
            .unwrap();
        store
            .create("b.com".to_string(), "t".to_string())
            .await
            .unwrap();

        // Third should fail (all active)
        let result = store.create("c.com".to_string(), "t".to_string()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn session_store_evicts_completed() {
        let store = SessionStore::new(2);
        let id1 = store
            .create("a.com".to_string(), "t".to_string())
            .await
            .unwrap();
        store
            .create("b.com".to_string(), "t".to_string())
            .await
            .unwrap();

        // Mark first as completed
        store
            .update_state(&id1, SessionState::Completed)
            .await
            .unwrap();

        // Third should succeed now (evicted completed session)
        let result = store.create("c.com".to_string(), "t".to_string()).await;
        assert!(result.is_ok());
    }

    #[test]
    fn generate_proof_produces_valid_structure() {
        let kp = NotaryKeyPair::generate();
        let body = r#"{"voter": {"status": "Active"}}"#;
        let cert_hash = zktls_core::sha512_hash(b"test-cert");

        let proof = generate_proof("example.com", body, &cert_hash, &kp);

        assert_eq!(proof.server_hostname, "example.com");
        assert_eq!(proof.certificate_hash, cert_hash);
        assert_eq!(proof.transcript_commitment.len(), 64);
        assert_eq!(proof.notary_signature.len(), 64);
        assert_eq!(proof.notary_public_key.len(), 32);
    }

    #[test]
    fn generate_proof_signature_is_verifiable() {
        let kp = NotaryKeyPair::generate();
        let body = r#"{"data": "test"}"#;
        let cert_hash = zktls_core::sha512_hash(b"cert");

        let proof = generate_proof("example.com", body, &cert_hash, &kp);

        // Reconstruct the signing message and verify
        let signing_msg = build_signing_message(
            &proof.server_hostname,
            &proof.certificate_hash,
            &proof.transcript_commitment,
            &proof.session_timestamp,
        );

        let sig = ed25519_dalek::Signature::from_bytes(
            proof.notary_signature.as_slice().try_into().unwrap(),
        );
        let vk = kp.verifying_key();
        assert!(ed25519_dalek::Verifier::verify(&vk, &signing_msg, &sig).is_ok());
    }

    #[test]
    fn extract_fields_disclosed_and_redacted() {
        let body = r#"{
            "voter": {
                "status": "Active",
                "first": "John",
                "last": "Doe"
            },
            "residence": {
                "physicalState": "UT"
            }
        }"#;

        let fields = vec![
            FieldDefinition {
                name: "status".to_string(),
                json_path: "voter.status".to_string(),
                field_type: FieldType::String,
                required: true,
                validation_pattern: None,
                description: "Status".to_string(),
            },
            FieldDefinition {
                name: "state".to_string(),
                json_path: "residence.physicalState".to_string(),
                field_type: FieldType::String,
                required: true,
                validation_pattern: None,
                description: "State".to_string(),
            },
            FieldDefinition {
                name: "firstName".to_string(),
                json_path: "voter.first".to_string(),
                field_type: FieldType::String,
                required: false,
                validation_pattern: None,
                description: "First name".to_string(),
            },
        ];

        let disclosure = DisclosureMask {
            disclosed_paths: vec![
                "voter.status".to_string(),
                "residence.physicalState".to_string(),
            ],
            redacted_paths: vec!["voter.first".to_string()],
        };

        let (disclosed, redacted) = extract_fields(body, &fields, &disclosure).unwrap();

        assert_eq!(disclosed.len(), 2);
        assert_eq!(disclosed["status"], "Active");
        assert_eq!(disclosed["state"], "UT");
        assert_eq!(redacted.len(), 1);
        assert_eq!(redacted[0].len(), 64); // SHA-512
    }

    #[test]
    fn extract_fields_missing_required() {
        let body = r#"{"other": "data"}"#;

        let fields = vec![FieldDefinition {
            name: "status".to_string(),
            json_path: "voter.status".to_string(),
            field_type: FieldType::String,
            required: true,
            validation_pattern: None,
            description: "Status".to_string(),
        }];

        let disclosure = DisclosureMask {
            disclosed_paths: vec!["voter.status".to_string()],
            redacted_paths: vec![],
        };

        let result = extract_fields(body, &fields, &disclosure);
        assert!(result.is_err());
    }

    #[test]
    fn navigate_json_path_works() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{"a": {"b": {"c": 42}}}"#,
        )
        .unwrap();

        assert_eq!(navigate_json_path(&json, "a.b.c"), Some(&serde_json::json!(42)));
        assert!(navigate_json_path(&json, "a.b.d").is_none());
        assert!(navigate_json_path(&json, "x.y").is_none());
    }
}
