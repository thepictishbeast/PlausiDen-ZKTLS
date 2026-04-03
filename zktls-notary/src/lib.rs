//! # zktls-notary
//!
//! Notary service that co-signs TLS sessions for zkTLS identity verification.
//!
//! A notary is a trusted third party that participates in a TLS handshake using
//! a multi-party computation (MPC) protocol. The notary sees the encrypted traffic
//! but cooperates with the client to decrypt it, ensuring that:
//!
//! 1. The client actually connected to the claimed server (not a local fake).
//! 2. The server's response is authentic and unmodified.
//! 3. The notary can attest to these facts without learning the full plaintext
//!    (in advanced MPC modes) or with a commitment to not retain it.
//!
//! This crate provides the notary-side logic: session management, TLS co-signing,
//! and proof generation. It is designed to run as a standalone service or be
//! embedded in a larger application.
//!
//! ## Architecture
//!
//! ```text
//! Client                    Notary                   Target Server
//!   |                         |                            |
//!   |--- initiate session --->|                            |
//!   |                         |                            |
//!   |<====== MPC-TLS handshake (three-party) ============>|
//!   |                         |                            |
//!   |--- request page ------->|--- forward (co-signed) -->|
//!   |                         |                            |
//!   |<-- response (attested) -|<-- response --------------|
//!   |                         |                            |
//!   |--- finalize proof ----->|                            |
//!   |<-- signed proof --------|                            |
//! ```

use zktls_core::SessionProof;

/// Configuration for the notary service.
///
/// Controls which servers are allowed, session timeouts, and
/// the notary's signing key material.
#[derive(Debug, Clone)]
pub struct NotaryConfig {
    /// Maximum number of concurrent notarization sessions.
    pub max_concurrent_sessions: usize,

    /// How long a session can remain open before it is forcibly closed, in seconds.
    pub session_timeout_secs: u64,

    /// Allowlist of server hostnames that this notary will co-sign sessions for.
    /// If empty, all servers are allowed (not recommended for production).
    pub allowed_hostnames: Vec<String>,

    /// The address and port the notary service listens on.
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

/// Represents an active notarization session between the client and notary.
///
/// Each session tracks the target server, the TLS transcript commitment being
/// built, and the session's lifecycle state.
#[derive(Debug)]
pub struct NotarySession {
    /// Unique identifier for this session.
    pub session_id: String,

    /// The target server hostname.
    pub target_hostname: String,

    /// Current state of the session.
    pub state: SessionState,
}

/// The lifecycle states of a notary session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// Session created, waiting for TLS handshake to begin.
    Initialized,

    /// TLS handshake in progress with the target server.
    Handshaking,

    /// Session is active; data is being exchanged and committed.
    Active,

    /// Session is finalizing; generating the signed proof.
    Finalizing,

    /// Session completed successfully; proof has been issued.
    Completed,

    /// Session failed or was cancelled.
    Failed(String),
}

/// Trait for notary implementations.
///
/// Different notary backends may use different MPC protocols, signing schemes,
/// or deployment models (local, remote, decentralized). This trait abstracts
/// over those differences.
pub trait Notarize {
    /// The error type returned by this notary implementation.
    type Error: std::error::Error;

    /// Begin a new notarization session for the given target hostname.
    ///
    /// Returns a session handle that can be used to drive the notarization
    /// protocol forward.
    fn begin_session(&mut self, target_hostname: &str) -> Result<NotarySession, Self::Error>;

    /// Finalize a session and produce a signed [`SessionProof`].
    ///
    /// This consumes the session. After finalization, the session cannot
    /// be reused.
    fn finalize_session(&mut self, session: NotarySession) -> Result<SessionProof, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sane_values() {
        let config = NotaryConfig::default();
        assert_eq!(config.max_concurrent_sessions, 100);
        assert_eq!(config.session_timeout_secs, 300);
        assert!(config.allowed_hostnames.is_empty());
        assert_eq!(config.listen_addr, "127.0.0.1:7443");
    }

    #[test]
    fn session_state_equality() {
        assert_eq!(SessionState::Initialized, SessionState::Initialized);
        assert_eq!(SessionState::Active, SessionState::Active);
        assert_ne!(SessionState::Initialized, SessionState::Active);
        assert_eq!(
            SessionState::Failed("timeout".to_string()),
            SessionState::Failed("timeout".to_string())
        );
    }
}
