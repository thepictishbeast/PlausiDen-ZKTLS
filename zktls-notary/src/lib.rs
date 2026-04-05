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
//!
//! ## Deployment Model
//!
//! For the initial deployment, this notary uses a **trusted fetch** model:
//! the notary itself fetches the target URL over TLS, verifies the server
//! certificate, commits to the response, and signs the proof. This is simpler
//! than full MPC-TLS but requires trusting the notary operator.
//!
//! Future versions will implement MPC-TLS where the notary co-signs without
//! seeing the full plaintext.

pub mod error;
pub mod keys;
pub mod server;
pub mod session;

pub use error::NotaryError;
pub use keys::NotaryKeyPair;
pub use server::{NotaryConfig, NotaryServer};
pub use session::{NotarySession, SessionState};
