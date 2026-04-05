//! Notary error types.

use thiserror::Error;

/// Errors from the notary service.
#[derive(Debug, Error)]
pub enum NotaryError {
    /// The target hostname is not in the allowlist.
    #[error("hostname not allowed: {0}")]
    HostnameNotAllowed(String),

    /// Too many concurrent sessions.
    #[error("max concurrent sessions ({0}) reached")]
    TooManySessions(usize),

    /// The session was not found.
    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// The session is in the wrong state for the requested operation.
    #[error("session {id} in state {state}, expected {expected}")]
    WrongState {
        /// The session ID.
        id: String,
        /// Current state.
        state: String,
        /// Expected state.
        expected: String,
    },

    /// Failed to fetch the target URL.
    #[error("fetch failed: {0}")]
    FetchFailed(String),

    /// The target server returned a non-success status code.
    #[error("target returned HTTP {status}: {body}")]
    TargetError {
        /// HTTP status code.
        status: u16,
        /// Response body (truncated).
        body: String,
    },

    /// Failed to extract fields from the response.
    #[error("field extraction failed: {0}")]
    ExtractionFailed(String),

    /// Cryptographic signing failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// Session has expired.
    #[error("session {0} has expired")]
    SessionExpired(String),

    /// The template was not found.
    #[error("template not found: {0}")]
    TemplateNotFound(String),
}
