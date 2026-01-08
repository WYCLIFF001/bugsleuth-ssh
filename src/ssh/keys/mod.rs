/// SSH Host Key Management
/// CRITICAL: Real SSH clients require valid host key signatures
/// Without this, clients will reject connection with "Host key verification failed"

use anyhow::Result;
use bytes::{BytesMut};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::path::Path;
use tracing::{debug, info};


use crate::ssh::protocol::primitives::write_ssh_string;

/// SSH host key for server authentication
pub struct HostKey {
    private_key: RsaPrivateKey,
    public_key_blob: Vec<u8>,
}

impl HostKey {
    /// Load existing host key or generate new one
    pub fn load_or_generate(path: &Path) -> Result<Self> {
        if path.exists() {
            info!("Loading existing host key from: {}", path.display());
            Self::load_from_file(path)
        } else {
            info!("Generating new host key: {}", path.display());
            Self::generate_and_save(path)
        }
    }

    /// Load host key from PEM file
    fn load_from_file(path: &Path) -> Result<Self> {
        let pem = std::fs::read_to_string(path)?;
        let private_key = RsaPrivateKey::from_pkcs8_pem(&pem)?;
        let public_key_blob = Self::build_public_key_blob(&private_key)?;

        debug!("Host key loaded successfully");
        Ok(Self {
            private_key,
            public_key_blob,
        })
    }

    /// Generate new 2048-bit RSA key and save to file
    fn generate_and_save(path: &Path) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;

        // Save to file
        let pem = private_key.to_pkcs8_pem(LineEnding::LF)?;

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(path, pem.as_bytes())?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600); // Read/write owner only
            std::fs::set_permissions(path, perms)?;
        }

        let public_key_blob = Self::build_public_key_blob(&private_key)?;

        info!("Generated new 2048-bit RSA host key");
        Ok(Self {
            private_key,
            public_key_blob,
        })
    }

    /// Build SSH public key blob in wire format
    /// Format: string "ssh-rsa" + mpint e + mpint n
    fn build_public_key_blob(key: &RsaPrivateKey) -> Result<Vec<u8>> {
        let public_key = RsaPublicKey::from(key);

        let mut blob = BytesMut::new();

        // Algorithm name
        write_ssh_string(&mut blob, b"ssh-rsa");

        // Public exponent (e)
        let e = public_key.e().to_bytes_be();
        write_ssh_string(&mut blob, &e);

        // Modulus (n)
        let n = public_key.n().to_bytes_be();
        write_ssh_string(&mut blob, &n);

        Ok(blob.to_vec())
    }

    /// Sign exchange hash (H) for KEX reply
    /// Returns SSH signature blob in wire format
    pub fn sign_exchange_hash(&self, hash: &[u8]) -> Result<Vec<u8>> {
        debug!("Signing exchange hash ({} bytes)", hash.len());

        // Create RSA-SHA256 signer
        let signing_key: SigningKey<Sha256> = SigningKey::new_unprefixed(self.private_key.clone());
        // Sign the hash
        let signature = signing_key.sign(hash);

        // Build SSH signature format:
        // string "ssh-rsa" + string signature_blob
        let mut sig_blob = BytesMut::new();
        write_ssh_string(&mut sig_blob, b"ssh-rsa");
        write_ssh_string(&mut sig_blob, signature.to_bytes().as_ref());

        debug!("Signature generated ({} bytes)", sig_blob.len());
        Ok(sig_blob.to_vec())
    }

    /// Get public key blob for KEX reply
    pub fn public_key_blob(&self) -> &[u8] {
        &self.public_key_blob
    }

    /// Get fingerprint for logging/display
    pub fn fingerprint(&self) -> String {
        use sha2::Digest;
        let hash = Sha256::digest(&self.public_key_blob);

        // Format as SHA256:base64
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &hash
        );
        format!("SHA256:{}", b64)
    }
}

// Helper for base64 encoding
mod base64 {
    pub use base64::Engine;
    pub mod engine {
        pub mod general_purpose {
            pub use base64::engine::general_purpose::STANDARD;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_key_generation() -> Result<()> {
        let temp_dir = std::env::temp_dir();
        let key_path = temp_dir.join("test_host_key");

        // Clean up if exists
        let _ = std::fs::remove_file(&key_path);

        // Generate new key
        let key = HostKey::load_or_generate(&key_path)?;
        assert!(key_path.exists());

        // Check fingerprint format
        let fp = key.fingerprint();
        assert!(fp.starts_with("SHA256:"));

        // Clean up
        std::fs::remove_file(&key_path)?;

        Ok(())
    }

    #[test]
    fn test_sign_exchange_hash() -> Result<()> {
        let temp_dir = std::env::temp_dir();
        let key_path = temp_dir.join("test_sign_key");

        let _ = std::fs::remove_file(&key_path);

        let key = HostKey::load_or_generate(&key_path)?;

        // Sign some test data
        let test_hash = b"test exchange hash data here";
        let signature = key.sign_exchange_hash(test_hash)?;

        // Signature should be non-empty
        assert!(!signature.is_empty());

        // Clean up
        std::fs::remove_file(&key_path)?;

        Ok(())
    }
}