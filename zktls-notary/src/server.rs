//! HTTP server for the notary service.
//!
//! Exposes REST endpoints for clients to request notarized verifications.
//! The server manages sessions, fetches target URLs, generates commitments,
//! and returns signed proofs.

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};
use uuid::Uuid;
use zktls_core::{Attestation, DisclosureMask};
use zktls_templates::TemplateRegistry;

use crate::error::NotaryError;
use crate::keys::NotaryKeyPair;
use crate::session::{extract_fields, generate_proof, SessionState, SessionStore};

/// Configuration for the notary service.
#[derive(Debug, Clone)]
pub struct NotaryConfig {
    /// Maximum concurrent sessions.
    pub max_concurrent_sessions: usize,
    /// Session timeout in seconds.
    pub session_timeout_secs: u64,
    /// Allowlisted hostnames (empty = allow all).
    pub allowed_hostnames: Vec<String>,
    /// Listen address.
    pub listen_addr: String,
}

impl Default for NotaryConfig {
    fn default() -> Self {
        Self {
            max_concurrent_sessions: 100,
            session_timeout_secs: 300,
            allowed_hostnames: Vec::new(),
            listen_addr: "127.0.0.1:7443".to_string(),
        }
    }
}

/// Shared state for the notary server.
#[derive(Debug, Clone)]
pub struct NotaryState {
    /// The notary's signing keypair.
    pub keypair: Arc<NotaryKeyPair>,
    /// Session store.
    pub sessions: SessionStore,
    /// Template registry.
    pub templates: Arc<TemplateRegistry>,
    /// Hostname allowlist.
    pub allowed_hostnames: Vec<String>,
    /// HTTP client for fetching targets.
    pub http_client: reqwest::Client,
}

/// The notary server.
pub struct NotaryServer {
    config: NotaryConfig,
    state: NotaryState,
}

impl NotaryServer {
    /// Create a new notary server.
    pub fn new(
        config: NotaryConfig,
        keypair: NotaryKeyPair,
        templates: TemplateRegistry,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("PlausiDen-zkTLS-Notary/0.1")
            .build()
            .expect("failed to build HTTP client");

        let state = NotaryState {
            keypair: Arc::new(keypair),
            sessions: SessionStore::new(config.max_concurrent_sessions),
            templates: Arc::new(templates),
            allowed_hostnames: config.allowed_hostnames.clone(),
            http_client,
        };

        Self { config, state }
    }

    /// Build the Axum router with all notary endpoints.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/health", get(health))
            .route("/info", get(notary_info))
            .route("/notarize", post(notarize))
            .route("/session/{id}", get(get_session))
            .with_state(self.state.clone())
    }

    /// Get the configured listen address.
    pub fn listen_addr(&self) -> &str {
        &self.config.listen_addr
    }

    /// Get a reference to the internal state (for testing).
    pub fn state(&self) -> &NotaryState {
        &self.state
    }
}

// ─── Request / Response Types ──────────────────────────────────

/// Request to notarize a web interaction.
#[derive(Debug, Deserialize)]
pub struct NotarizeRequest {
    /// The template ID to use (e.g., "utah-voter-v1").
    pub template_id: String,
    /// Request body to send to the target server (for POST templates).
    pub request_body: Option<serde_json::Value>,
    /// Optional custom disclosure mask (overrides template default).
    pub disclosure: Option<DisclosureMask>,
}

/// Response from a successful notarization.
#[derive(Debug, Serialize)]
pub struct NotarizeResponse {
    /// Session ID for tracking.
    pub session_id: String,
    /// The signed session proof.
    pub proof: zktls_core::SessionProof,
    /// The attestation with disclosed/redacted fields.
    pub attestation: Attestation,
}

/// Notary info response.
#[derive(Debug, Serialize, Deserialize)]
pub struct NotaryInfoResponse {
    /// The notary's public key (hex-encoded).
    pub public_key: String,
    /// Notary name.
    pub name: String,
    /// Available template IDs.
    pub templates: Vec<String>,
    /// Active session count.
    pub active_sessions: usize,
}

/// Error response body.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

// ─── Handlers ──────────────────────────────────────────────────

/// Health check.
async fn health() -> &'static str {
    "ok"
}

/// Return notary info including public key and available templates.
async fn notary_info(State(state): State<NotaryState>) -> Json<NotaryInfoResponse> {
    let pub_key_hex = hex::encode(state.keypair.public_key_bytes());
    let template_ids: Vec<String> = state
        .templates
        .list_ids()
        .into_iter()
        .map(String::from)
        .collect();
    let active = state.sessions.active_count().await;

    Json(NotaryInfoResponse {
        public_key: pub_key_hex,
        name: "PlausiDen zkTLS Notary".to_string(),
        templates: template_ids,
        active_sessions: active,
    })
}

/// Perform a notarized fetch — the main endpoint.
///
/// 1. Validate the template exists and hostname is allowed
/// 2. Create a session
/// 3. Fetch the target URL
/// 4. Extract fields per template
/// 5. Generate proof and attestation
/// 6. Sign and return
async fn notarize(
    State(state): State<NotaryState>,
    Json(req): Json<NotarizeRequest>,
) -> Result<Json<NotarizeResponse>, (StatusCode, Json<ErrorResponse>)> {
    // 1. Look up template
    let template = state
        .templates
        .get(&req.template_id)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("template not found: {}", req.template_id),
                }),
            )
        })?
        .clone();

    // Check hostname allowlist
    if !state.allowed_hostnames.is_empty()
        && !state
            .allowed_hostnames
            .contains(&template.target.hostname)
    {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!("hostname not allowed: {}", template.target.hostname),
            }),
        ));
    }

    // 2. Create session
    let session_id = state
        .sessions
        .create(template.target.hostname.clone(), template.id.clone())
        .await
        .map_err(|e| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    info!(
        session_id = %session_id,
        template = %template.id,
        target = %template.target.hostname,
        "starting notarization"
    );

    // 3. Fetch the target URL
    state
        .sessions
        .update_state(&session_id, SessionState::Fetching)
        .await
        .ok();

    let url = format!(
        "https://{}{}",
        template.target.hostname, template.target.path
    );

    let response = match template.target.method {
        zktls_templates::HttpMethod::Get => state.http_client.get(&url).send().await,
        zktls_templates::HttpMethod::Post => {
            let body = req.request_body.unwrap_or(serde_json::Value::Null);
            state
                .http_client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
        }
    };

    let response = response.map_err(|e| {
        let msg = format!("fetch failed: {e}");
        error!(session_id = %session_id, %msg);
        let _ = futures_set_failed(&state, &session_id, &msg);
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse { error: msg }),
        )
    })?;

    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "(no body)".to_string());
        let msg = format!("target returned HTTP {}: {}", status.as_u16(), &body[..body.len().min(200)]);
        error!(session_id = %session_id, %msg);
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse { error: msg }),
        ));
    }

    let response_body = response.text().await.map_err(|e| {
        let msg = format!("failed to read response body: {e}");
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse { error: msg }),
        )
    })?;

    // Compute a certificate hash (in trusted-fetch mode, we hash the hostname as a stand-in;
    // full MPC-TLS would extract the actual certificate chain)
    let cert_hash = zktls_core::sha512_hash(
        format!("tls-cert:{}", template.target.hostname).as_bytes(),
    );

    // Store response
    state
        .sessions
        .store_response(&session_id, response_body.clone(), cert_hash.clone())
        .await
        .ok();

    // 4. Extract fields
    state
        .sessions
        .update_state(&session_id, SessionState::Committing)
        .await
        .ok();

    let disclosure = req.disclosure.unwrap_or(template.default_disclosure.clone());

    let (disclosed_fields, redacted_hashes) =
        extract_fields(&response_body, &template.fields, &disclosure).map_err(|e| {
            let msg = e.to_string();
            error!(session_id = %session_id, %msg);
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorResponse { error: msg }),
            )
        })?;

    // 5. Generate proof
    let proof = generate_proof(
        &template.target.hostname,
        &response_body,
        &cert_hash,
        &state.keypair,
    );

    // 6. Build attestation
    let attestation = Attestation {
        id: format!("att-{}", Uuid::new_v4()),
        claim_type: template.claim_type.clone(),
        session_proof_id: session_id.clone(),
        disclosed_fields,
        redacted_field_hashes: redacted_hashes,
        template_id: template.id.clone(),
        created_at: Utc::now(),
        expires_at: Some(Utc::now() + chrono::Duration::days(30)),
    };

    // Store completed proof
    state
        .sessions
        .store_proof(&session_id, proof.clone(), attestation.clone())
        .await
        .ok();

    info!(
        session_id = %session_id,
        template = %template.id,
        disclosed_fields = attestation.disclosed_fields.len(),
        redacted_fields = attestation.redacted_field_hashes.len(),
        "notarization complete"
    );

    Ok(Json(NotarizeResponse {
        session_id,
        proof,
        attestation,
    }))
}

/// Get session status.
async fn get_session(
    State(state): State<NotaryState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<crate::session::NotarySession>, (StatusCode, Json<ErrorResponse>)> {
    let session = state.sessions.get(&id).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    Ok(Json(session))
}

/// Helper to set a session as failed (fire-and-forget).
fn futures_set_failed(
    state: &NotaryState,
    session_id: &str,
    reason: &str,
) -> Result<(), NotaryError> {
    let sessions = state.sessions.clone();
    let id = session_id.to_string();
    let reason = reason.to_string();
    tokio::spawn(async move {
        let _ = sessions
            .update_state(&id, SessionState::Failed(reason))
            .await;
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_server() -> NotaryServer {
        let config = NotaryConfig::default();
        let keypair = NotaryKeyPair::generate();
        let templates = TemplateRegistry::new();
        NotaryServer::new(config, keypair, templates)
    }

    #[tokio::test]
    async fn health_endpoint() {
        let server = test_server();
        let app = server.router();

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn info_endpoint() {
        let server = test_server();
        let app = server.router();

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/info")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let info: NotaryInfoResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(info.public_key.len(), 64); // 32 bytes hex
        assert_eq!(info.name, "PlausiDen zkTLS Notary");
    }

    #[tokio::test]
    async fn notarize_unknown_template_returns_404() {
        let server = test_server();
        let app = server.router();

        let req_body = serde_json::json!({
            "template_id": "nonexistent-v1",
        });

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/notarize")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
