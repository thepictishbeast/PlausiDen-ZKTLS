//! # zktls-templates
//!
//! Template definitions for zkTLS verification targets.
//!
//! A template describes how to interact with a specific verification target
//! (e.g., a state government voter registration lookup) and how to extract
//! structured claims from the server's response. Templates are the bridge
//! between raw TLS session data and meaningful attestations.
//!
//! Each template specifies:
//!
//! - **Target server** — the hostname and path to connect to.
//! - **Request format** — how to construct the HTTP request (URL parameters,
//!   headers, POST body).
//! - **Response extraction** — JSONPath or regex patterns that pull structured
//!   fields out of the server's response.
//! - **Field definitions** — names, types, and validation rules for each
//!   extractable field, along with which fields are safe to disclose by default.
//!
//! Templates are versioned and identified by a unique ID. When a server changes
//! its API format, a new template version is published.
//!
//! ## Example
//!
//! A Utah voter registration template might define:
//! - Target: `votesearch.utah.gov`
//! - Extraction: JSON fields `voterStatus`, `county`, `party`
//! - Default disclosure: `voterStatus` only (minimal proof of registration)

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use zktls_core::DisclosureMask;

/// A verification template that describes how to notarize a specific web
/// interaction and extract structured claims from it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationTemplate {
    /// Unique identifier for this template (e.g., "utah-voter-v1").
    pub id: String,

    /// Human-readable name (e.g., "Utah Voter Registration Lookup").
    pub name: String,

    /// Description of what this template verifies.
    pub description: String,

    /// Version of this template. Incremented when the target changes format.
    pub version: u32,

    /// The target server configuration.
    pub target: TargetServer,

    /// Field definitions describing what can be extracted from the response.
    pub fields: Vec<FieldDefinition>,

    /// The default disclosure mask (which fields to reveal vs. redact).
    pub default_disclosure: DisclosureMask,

    /// The claim type that attestations from this template will carry.
    pub claim_type: String,
}

/// Configuration for the target server that will be notarized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetServer {
    /// The server's hostname (e.g., "votesearch.utah.gov").
    pub hostname: String,

    /// The URL path to request (e.g., "/api/voter/search").
    pub path: String,

    /// HTTP method (GET or POST).
    pub method: HttpMethod,

    /// Expected response content type.
    pub expected_content_type: String,
}

/// HTTP methods supported by templates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HttpMethod {
    /// HTTP GET request.
    Get,
    /// HTTP POST request.
    Post,
}

/// Definition of a single extractable field from the server's response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDefinition {
    /// The field's name as it will appear in the attestation.
    pub name: String,

    /// A dot-separated path into the response JSON (e.g., "data.voter.status").
    pub json_path: String,

    /// The expected type of this field's value.
    pub field_type: FieldType,

    /// Whether this field is required for a valid attestation.
    pub required: bool,

    /// Optional regex pattern that the field's value must match.
    pub validation_pattern: Option<String>,

    /// Human-readable description of what this field represents.
    pub description: String,
}

/// The data type of an extractable field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FieldType {
    /// A text string.
    String,
    /// A boolean value.
    Boolean,
    /// An integer number.
    Integer,
    /// A date in ISO 8601 format.
    Date,
}

/// Registry of available verification templates.
///
/// Applications load templates from this registry to configure their
/// zkTLS verification flows.
#[derive(Debug, Default)]
pub struct TemplateRegistry {
    templates: Vec<VerificationTemplate>,
}

impl TemplateRegistry {
    /// Create an empty template registry.
    pub fn new() -> Self {
        Self {
            templates: Vec::new(),
        }
    }

    /// Register a new template.
    pub fn register(&mut self, template: VerificationTemplate) {
        self.templates.push(template);
    }

    /// Look up a template by its unique ID.
    pub fn get(&self, id: &str) -> Option<&VerificationTemplate> {
        self.templates.iter().find(|t| t.id == id)
    }

    /// List all registered template IDs.
    pub fn list_ids(&self) -> Vec<&str> {
        self.templates.iter().map(|t| t.id.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_template() -> VerificationTemplate {
        VerificationTemplate {
            id: "utah-voter-v1".to_string(),
            name: "Utah Voter Registration Lookup".to_string(),
            description: "Verifies active voter registration in the state of Utah.".to_string(),
            version: 1,
            target: TargetServer {
                hostname: "votesearch.utah.gov".to_string(),
                path: "/api/search".to_string(),
                method: HttpMethod::Get,
                expected_content_type: "application/json".to_string(),
            },
            fields: vec![
                FieldDefinition {
                    name: "status".to_string(),
                    json_path: "data.voterStatus".to_string(),
                    field_type: FieldType::String,
                    required: true,
                    validation_pattern: Some("^(Active|Inactive)$".to_string()),
                    description: "Voter registration status.".to_string(),
                },
                FieldDefinition {
                    name: "county".to_string(),
                    json_path: "data.county".to_string(),
                    field_type: FieldType::String,
                    required: false,
                    validation_pattern: None,
                    description: "County of registration.".to_string(),
                },
            ],
            default_disclosure: DisclosureMask {
                disclosed_paths: vec!["data.voterStatus".to_string()],
                redacted_paths: vec![
                    "data.county".to_string(),
                    "data.name".to_string(),
                    "data.address".to_string(),
                ],
            },
            claim_type: "voter_registration".to_string(),
        }
    }

    #[test]
    fn template_serializes_roundtrip() {
        let template = sample_template();
        let json = serde_json::to_string(&template).expect("serialization should succeed");
        let decoded: VerificationTemplate =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(decoded.id, "utah-voter-v1");
        assert_eq!(decoded.fields.len(), 2);
        assert_eq!(decoded.target.hostname, "votesearch.utah.gov");
    }

    #[test]
    fn registry_register_and_lookup() {
        let mut registry = TemplateRegistry::new();
        registry.register(sample_template());

        assert_eq!(registry.list_ids(), vec!["utah-voter-v1"]);
        let found = registry.get("utah-voter-v1");
        assert!(found.is_some());
        assert_eq!(
            found.expect("template should exist").name,
            "Utah Voter Registration Lookup"
        );
    }

    #[test]
    fn registry_returns_none_for_unknown_id() {
        let registry = TemplateRegistry::new();
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn http_method_equality() {
        assert_eq!(HttpMethod::Get, HttpMethod::Get);
        assert_eq!(HttpMethod::Post, HttpMethod::Post);
        assert_ne!(HttpMethod::Get, HttpMethod::Post);
    }
}
