//! zkTLS Notary Service — standalone binary.
//!
//! Runs the notary HTTP server with configuration from environment variables
//! or command-line arguments. The notary generates and persists its Ed25519
//! signing key, loads verification templates, and serves the /notarize API.

use std::path::PathBuf;
use tokio::net::TcpListener;
use tracing::{info, warn};
use zktls_core::DisclosureMask;
use zktls_notary::{NotaryConfig, NotaryKeyPair, NotaryServer};
use zktls_templates::{
    FieldDefinition, FieldType, HttpMethod, TargetServer, TemplateRegistry, VerificationTemplate,
};

/// Load or generate the notary's Ed25519 key pair.
///
/// If a key file exists at the given path, loads it. Otherwise generates
/// a new key pair and saves it. The file contains the raw 32-byte seed.
fn load_or_generate_key(path: &PathBuf) -> NotaryKeyPair {
    if path.exists() {
        let seed_bytes = std::fs::read(path).expect("failed to read key file");
        if seed_bytes.len() != 32 {
            panic!("key file must be exactly 32 bytes, got {}", seed_bytes.len());
        }
        let seed: [u8; 32] = seed_bytes.try_into().unwrap();
        info!(path = %path.display(), "loaded existing notary key");
        NotaryKeyPair::from_seed(&seed)
    } else {
        let kp = NotaryKeyPair::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(path, kp.seed()).expect("failed to write key file");
        // Restrict permissions to owner-only
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).ok();
        }
        info!(path = %path.display(), "generated new notary key");
        kp
    }
}

/// Build the Utah voter registration template.
///
/// Derived from HAR analysis of votesearch.utah.gov. The template defines
/// which fields to extract from the API response and which to disclose
/// vs. redact in the attestation.
fn utah_voter_template() -> VerificationTemplate {
    VerificationTemplate {
        id: "utah-voter-v1".to_string(),
        name: "Utah Voter Registration Lookup".to_string(),
        description: "Verifies active voter registration via votesearch.utah.gov. \
            Requires first/last name, DOB, and address. Reveals only registration \
            status and state; all PII is cryptographically redacted."
            .to_string(),
        version: 1,
        target: TargetServer {
            hostname: "votesearch.utah.gov".to_string(),
            path: "/voter-search/public-api/my-voter-profile".to_string(),
            method: HttpMethod::Post,
            expected_content_type: "application/json".to_string(),
        },
        fields: vec![
            FieldDefinition {
                name: "status".to_string(),
                json_path: "voter.status".to_string(),
                field_type: FieldType::String,
                required: true,
                validation_pattern: Some(
                    "^(Active|Inactive|Cancelled|Suspended)$".to_string(),
                ),
                description: "Voter registration status.".to_string(),
            },
            FieldDefinition {
                name: "state".to_string(),
                json_path: "residence.physicalState".to_string(),
                field_type: FieldType::String,
                required: true,
                validation_pattern: Some("^UT$".to_string()),
                description: "State of residence.".to_string(),
            },
            FieldDefinition {
                name: "errorMessage".to_string(),
                json_path: "errorMessage".to_string(),
                field_type: FieldType::String,
                required: false,
                validation_pattern: None,
                description: "API error message (null on success).".to_string(),
            },
        ],
        default_disclosure: DisclosureMask {
            disclosed_paths: vec![
                "voter.status".to_string(),
                "residence.physicalState".to_string(),
                "errorMessage".to_string(),
            ],
            redacted_paths: vec![
                "voter.first".to_string(),
                "voter.middle".to_string(),
                "voter.last".to_string(),
                "voter.party".to_string(),
                "voter.voterId".to_string(),
                "residence.physicalAddress1".to_string(),
                "residence.physicalCity".to_string(),
                "residence.physicalZip".to_string(),
                "countyName".to_string(),
                "precinctId".to_string(),
            ],
        },
        claim_type: "voter_registration".to_string(),
    }
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zktls_notary=info".parse().unwrap()),
        )
        .json()
        .init();

    // Configuration from environment
    let listen_addr = std::env::var("NOTARY_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:7443".to_string());
    let key_path = PathBuf::from(
        std::env::var("NOTARY_KEY_PATH")
            .unwrap_or_else(|_| "/var/lib/zktls-notary/notary.key".to_string()),
    );
    let max_sessions: usize = std::env::var("NOTARY_MAX_SESSIONS")
        .unwrap_or_else(|_| "100".to_string())
        .parse()
        .expect("NOTARY_MAX_SESSIONS must be a number");

    // Load or generate key
    let keypair = load_or_generate_key(&key_path);
    let public_key_hex = hex::encode(keypair.public_key_bytes());
    info!(public_key = %public_key_hex, "notary public key");

    // Build template registry
    let mut templates = TemplateRegistry::new();
    templates.register(utah_voter_template());
    info!(templates = templates.list_ids().len(), "loaded templates");

    // Build config
    let config = NotaryConfig {
        max_concurrent_sessions: max_sessions,
        session_timeout_secs: 300,
        allowed_hostnames: vec!["votesearch.utah.gov".to_string()],
        listen_addr: listen_addr.clone(),
    };

    // Create and start server
    let server = NotaryServer::new(config, keypair, templates);
    let app = server.router();

    let listener = TcpListener::bind(&listen_addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {listen_addr}: {e}"));

    info!(addr = %listen_addr, "zkTLS notary service starting");
    warn!("deployment model: trusted-fetch (notary fetches target directly)");

    axum::serve(listener, app)
        .await
        .expect("server error");
}
