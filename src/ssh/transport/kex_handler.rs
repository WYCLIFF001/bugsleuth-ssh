/// Key Exchange Handler with Real Host Key Support

use anyhow::{Result, bail};
use bytes::{Bytes, BytesMut, BufMut};
use tracing::{debug, info, error};
use std::sync::Arc;

use crate::ssh::kex::{KexState, SessionKeys};
use crate::ssh::keys::HostKey;  // ADD THIS

/// Manages key exchange with real host key signing
pub struct KexHandler {
    kex: KexState,
    kex_complete: bool,
    client_version: String,
    server_version: String,
    host_key: Arc<HostKey>,  // ADD THIS
}

impl KexHandler {
    pub fn new(
        client_version: String,
        server_version: String,
        host_key: Arc<HostKey>,  // ADD THIS PARAMETER
    ) -> Self {
        Self {
            kex: KexState::new(),
            kex_complete: false,
            client_version,
            server_version,
            host_key,  // ADD THIS
        }
    }

    pub async fn process_kex_message(&mut self, msg_type: u8, payload: &[u8]) -> Result<Option<Bytes>> {
        match msg_type {
            20 => self.handle_kexinit(payload).await,
            30 => self.handle_kex_init(payload).await,
            21 => self.handle_newkeys(payload).await,
            _ => {
                error!("Unexpected KEX message type: {}", msg_type);
                bail!("Invalid KEX message type: {}", msg_type)
            }
        }
    }

    async fn handle_kexinit(&mut self, payload: &[u8]) -> Result<Option<Bytes>> {
        info!("Processing KEXINIT from client");

        self.kex.parse_client_kexinit(Bytes::copy_from_slice(payload))?;
        debug!("Algorithms negotiated");

        self.kex.generate_keys()?;
        debug!("Ephemeral keys generated");

        let our_kexinit = self.kex.build_server_kexinit()?;
        info!("Sending KEXINIT to client");

        Ok(Some(our_kexinit))
    }

    async fn handle_kex_init(&mut self, payload: &[u8]) -> Result<Option<Bytes>> {
        info!("Processing KEX init from client");

        self.kex.parse_kex_init(Bytes::copy_from_slice(payload))?;
        debug!("Client public key received");

        self.kex.compute_shared_secret()?;
        debug!("Shared secret computed");

        self.kex.compute_exchange_hash(
            &self.client_version,
            &self.server_version,
        )?;
        debug!("Exchange hash computed");

        // USE REAL HOST KEY AND SIGNATURE (not dummy!)
        let host_key_blob = self.host_key.public_key_blob();

        // Get exchange hash for signing
        let exchange_hash = self.kex.exchange_hash()
            .ok_or_else(|| anyhow::anyhow!("Exchange hash not computed"))?;

        // Sign with real host key
        let signature = self.host_key.sign_exchange_hash(exchange_hash)?;

        info!("🔑 Signed exchange hash with host key");

        // Build KEX reply with real signature
        let kex_reply = self.kex.build_kex_reply(host_key_blob, &signature)?;

        debug!("KEX reply prepared with real signature");
        Ok(Some(kex_reply))
    }

    async fn handle_newkeys(&mut self, _payload: &[u8]) -> Result<Option<Bytes>> {
        info!("Received NEWKEYS from client");

        let mut newkeys = BytesMut::new();
        newkeys.put_u8(21); // SSH_MSG_NEWKEYS

        info!("Sending NEWKEYS - KEX complete");
        self.kex_complete = true;

        Ok(Some(newkeys.freeze()))
    }

    pub fn is_complete(&self) -> bool {
        self.kex_complete
    }

    pub fn algorithms(&self) -> Option<&crate::ssh::kex::algorithms::NegotiatedAlgorithms> {
        self.kex.negotiated_algorithms()
    }

    pub fn derive_keys(&self) -> Result<SessionKeys> {
        self.kex.derive_keys()
    }
}