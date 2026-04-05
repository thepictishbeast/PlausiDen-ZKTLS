//! Ed25519 key management for the notary.
//!
//! The notary signs session proofs with Ed25519, providing 128-bit security
//! and small signatures (64 bytes). Keys can be generated fresh or loaded
//! from bytes for persistent deployments.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

/// An Ed25519 key pair for the notary.
///
/// The signing key is used to produce session proof signatures.
/// The verifying key (public key) is distributed to relying parties
/// so they can verify proofs without trusting the notary at verification time.
#[derive(Debug)]
pub struct NotaryKeyPair {
    signing_key: SigningKey,
}

impl NotaryKeyPair {
    /// Generate a new random Ed25519 key pair.
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Load a key pair from a 32-byte secret seed.
    ///
    /// Use this to restore a previously generated key pair from persistent storage.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    /// Get the 32-byte secret seed for persistent storage.
    ///
    /// Handle with care — this is the notary's private key material.
    pub fn seed(&self) -> &[u8; 32] {
        self.signing_key.as_bytes()
    }

    /// Get the public verifying key as 32 bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().as_bytes().to_vec()
    }

    /// Get the verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign a message, returning the 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).to_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn generate_produces_valid_keypair() {
        let kp = NotaryKeyPair::generate();
        assert_eq!(kp.public_key_bytes().len(), 32);
        assert_eq!(kp.seed().len(), 32);
    }

    #[test]
    fn from_seed_roundtrips() {
        let kp1 = NotaryKeyPair::generate();
        let seed = *kp1.seed();
        let kp2 = NotaryKeyPair::from_seed(&seed);
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[test]
    fn sign_produces_valid_signature() {
        let kp = NotaryKeyPair::generate();
        let message = b"test message for signing";
        let sig_bytes = kp.sign(message);
        assert_eq!(sig_bytes.len(), 64);

        // Verify with the public key
        let sig = ed25519_dalek::Signature::from_bytes(
            sig_bytes.as_slice().try_into().expect("64 bytes"),
        );
        kp.verifying_key()
            .verify(message, &sig)
            .expect("signature should verify");
    }

    #[test]
    fn different_keys_produce_different_signatures() {
        let kp1 = NotaryKeyPair::generate();
        let kp2 = NotaryKeyPair::generate();
        let message = b"same message";
        assert_ne!(kp1.sign(message), kp2.sign(message));
    }

    #[test]
    fn signature_fails_with_wrong_key() {
        let kp1 = NotaryKeyPair::generate();
        let kp2 = NotaryKeyPair::generate();
        let message = b"test message";
        let sig_bytes = kp1.sign(message);

        let sig = ed25519_dalek::Signature::from_bytes(
            sig_bytes.as_slice().try_into().expect("64 bytes"),
        );
        // Verifying with kp2's public key should fail
        assert!(kp2.verifying_key().verify(message, &sig).is_err());
    }
}
