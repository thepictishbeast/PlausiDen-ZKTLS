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
        // Build HTTP client with browser-like TLS fingerprint.
        // Cookie store enabled for CSRF token flows (Utah requires XSRF-TOKEN cookie).
        // User-Agent rotated per-request in the handler, not set here.
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .cookie_store(true)
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

    /// Rotate the User-Agent to a realistic browser string.
    /// Called periodically to avoid fingerprinting by target servers.
    fn browser_user_agent() -> &'static str {
        // Realistic browser UAs — rotated per-request to avoid profiling
        const USER_AGENTS: &[&str] = &[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        ];
        use std::sync::atomic::{AtomicUsize, Ordering};
        static INDEX: AtomicUsize = AtomicUsize::new(0);
        let idx = INDEX.fetch_add(1, Ordering::Relaxed) % USER_AGENTS.len();
        USER_AGENTS[idx]
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

    // 3. Fetch the target URL with anti-fingerprinting measures
    state
        .sessions
        .update_state(&session_id, SessionState::Fetching)
        .await
        .ok();

    let url = format!(
        "https://{}{}",
        template.target.hostname, template.target.path
    );
    let ua = NotaryServer::browser_user_agent();

    // Anti-fingerprinting: random 1-5s jitter before hitting target
    let jitter_ms = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        session_id.hash(&mut h);
        (h.finish() % 4000 + 1000) as u64 // 1000-5000ms
    };
    tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;

    // Build a fresh HTTP client for THIS notarization. Sharing state.http_client
    // across requests causes cookie-jar pollution: the second call's CSRF GET
    // sees stale XSRF-TOKEN/F5-affinity cookies from the previous run, the gov
    // portal serves a session-already-active response without setting fresh
    // cookies, and the POST then 404s. A per-request client guarantees a clean
    // jar (Tim demo 2026-04-27).
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .cookie_store(true)
        .build()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("failed to build http client: {e}"),
                }),
            )
        })?;

    // Step A: Acquire CSRF token if the template declares a CSRF config.
    // This is generic — works for Spring Security (XSRF-TOKEN), Django, etc.
    let mut csrf_token: Option<(String, String)> = None; // (header_name, token_value)
    if let Some(ref csrf_cfg) = template.target.csrf {
        let csrf_url = format!(
            "https://{}{}",
            template.target.hostname, csrf_cfg.fetch_path
        );
        let csrf_res = http_client
            .get(&csrf_url)
            .header("User-Agent", ua)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Accept-Encoding", "gzip, deflate, br")
            .header("DNT", "1")
            .header("Connection", "keep-alive")
            .header("Sec-Fetch-Dest", "document")
            .header("Sec-Fetch-Mode", "navigate")
            .header("Sec-Fetch-Site", "none")
            .header("Sec-Fetch-User", "?1")
            .header("Upgrade-Insecure-Requests", "1")
            .send()
            .await;

        match csrf_res {
            Ok(csrf_response) => {
                let csrf_status = csrf_response.status();
                let cookie_count = csrf_response.headers().get_all("set-cookie").iter().count();
                let cookie_prefix = format!("{}=", csrf_cfg.cookie_name);
                for cookie_str in csrf_response.headers().get_all("set-cookie") {
                    if let Ok(val) = cookie_str.to_str() {
                        if val.starts_with(&cookie_prefix) {
                            let token = val[cookie_prefix.len()..]
                                .split(';')
                                .next()
                                .unwrap_or("");
                            if !token.is_empty() {
                                csrf_token = Some((
                                    csrf_cfg.header_name.clone(),
                                    token.to_string(),
                                ));
                            }
                        }
                    }
                }
                info!(
                    session_id = %session_id,
                    csrf_status = %csrf_status,
                    set_cookie_headers = cookie_count,
                    csrf_token_extracted = csrf_token.is_some(),
                    "csrf fetch complete"
                );
            }
            Err(e) => {
                error!(session_id = %session_id, "csrf fetch failed: {}", e);
            }
        }

        // Brief pause between CSRF fetch and actual request (human-like)
        tokio::time::sleep(std::time::Duration::from_millis(500 + jitter_ms % 1500)).await;
    }

    // Step B: Make the actual request with browser-like headers
    let response = match template.target.method {
        zktls_templates::HttpMethod::Get => {
            http_client
                .get(&url)
                .header("User-Agent", ua)
                .header("Accept", "application/json, text/plain, */*")
                .header("Accept-Language", "en-US,en;q=0.9")
                .header("Accept-Encoding", "gzip, deflate, br")
                .header("DNT", "1")
                .header("Connection", "keep-alive")
                .header("Sec-Fetch-Dest", "empty")
                .header("Sec-Fetch-Mode", "cors")
                .header("Sec-Fetch-Site", "same-origin")
                .send()
                .await
        }
        zktls_templates::HttpMethod::Post => {
            let body = req.request_body.unwrap_or(serde_json::Value::Null);
            let referer = template
                .target
                .referer_path
                .as_deref()
                .map(|p| format!("https://{}{}", template.target.hostname, p))
                .unwrap_or_else(|| format!("https://{}/", template.target.hostname));

            // Derive sec-ch-ua from selected UA to keep headers consistent
            let (ch_ua, ch_platform) = if ua.contains("Chrome/131") {
                ("\"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\", \"Google Chrome\";v=\"131\"", if ua.contains("Windows") { "\"Windows\"" } else if ua.contains("Macintosh") { "\"macOS\"" } else { "\"Linux\"" })
            } else if ua.contains("Firefox") {
                ("\"Firefox\";v=\"133\"", if ua.contains("Windows") { "\"Windows\"" } else { "\"Linux\"" })
            } else {
                ("\"Safari\";v=\"18\"", "\"macOS\"")
            };

            let mut req_builder = http_client
                .post(&url)
                .header("User-Agent", ua)
                .header("Content-Type", "application/json;charset=UTF-8")
                .header("Accept", "application/json, text/plain, */*")
                .header("Accept-Language", "en-US,en;q=0.9")
                .header("Accept-Encoding", "gzip, deflate, br")
                .header(
                    "Origin",
                    format!("https://{}", template.target.hostname),
                )
                .header("Referer", referer)
                .header("DNT", "1")
                .header("Connection", "keep-alive")
                // Sec-Fetch metadata — tells the server this is a same-origin XHR
                .header("Sec-Fetch-Dest", "empty")
                .header("Sec-Fetch-Mode", "cors")
                .header("Sec-Fetch-Site", "same-origin")
                // Client hints — Chrome sends these on every request
                .header("sec-ch-ua", ch_ua)
                .header("sec-ch-ua-mobile", "?0")
                .header("sec-ch-ua-platform", ch_platform);

            // Attach CSRF token if acquired (generic — header name from template)
            if let Some((ref header_name, ref token_value)) = csrf_token {
                req_builder = req_builder.header(header_name.as_str(), token_value.as_str());
            }

            req_builder.json(&body).send().await
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
        // Do NOT log the response body — it may contain PII from the gov portal.
        // Only log the HTTP status code, URL, body byte length, and template info.
        let resp_url = response.url().to_string();
        let resp_bytes = response.bytes().await.map(|b| b.len()).unwrap_or(0);
        let msg = format!(
            "target returned HTTP {} for template={} url={} body_bytes={}",
            status.as_u16(),
            template.id,
            resp_url,
            resp_bytes,
        );
        error!(session_id = %session_id, %msg);
        let _ = futures_set_failed(&state, &session_id, &msg);
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
