/// SSH Transport Layer - Fully Integrated with Encryption & Real Host Key

use anyhow::{Result, bail};
use bytes::{BytesMut, Bytes, BufMut, Buf};
use tracing::{debug, info, error};
use std::sync::Arc;

use crate::auth::AuthCache;
use crate::ssh::crypto::SshPacketCodec;
use crate::ssh::keys::HostKey;  // ADD THIS
use super::kex_handler::KexHandler;
use super::auth_handler::TransportAuthHandler;

pub const SSH_VERSION: &str = "SSH-2.0-SSH_Forwarder_0.1";
const MAX_HANDSHAKE_GARBAGE: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    WaitingIdent,
    KeyExchange,
    Authentication,
    Ready,
}

pub struct SshTransport {
    state: TransportState,
    client_version: Option<String>,
    garbage_bytes: usize,
    read_buffer: BytesMut,

    kex_handler: Option<KexHandler>,
    auth_handler: Option<TransportAuthHandler>,
    auth_cache: Arc<AuthCache>,
    host_key: Arc<HostKey>,  // ADD THIS

    // Encryption support
    codec: SshPacketCodec,
    encryption_enabled: bool,
}

impl SshTransport {
    pub fn new(auth_cache: Arc<AuthCache>, host_key: Arc<HostKey>) -> Self {  // ADD host_key PARAMETER
        Self {
            state: TransportState::WaitingIdent,
            client_version: None,
            garbage_bytes: 0,
            read_buffer: BytesMut::with_capacity(4096),
            kex_handler: None,
            auth_handler: None,
            auth_cache,
            host_key,  // ADD THIS
            codec: SshPacketCodec::new(),
            encryption_enabled: false,
        }
    }

    pub fn state(&self) -> TransportState {
        self.state
    }

    pub fn is_ready(&self) -> bool {
        self.state == TransportState::Ready
    }

    pub fn is_authenticated(&self) -> bool {
        self.auth_handler.as_ref()
            .map(|h| h.is_authenticated())
            .unwrap_or(false)
    }

    pub fn username(&self) -> Option<&str> {
        self.auth_handler.as_ref()
            .and_then(|h| h.username())
    }

    pub async fn process_transport_data(&mut self, data: &[u8]) -> Result<Option<Bytes>> {
        match self.state {
            TransportState::WaitingIdent => {
                self.read_buffer.put_slice(data);
                self.process_version_exchange()
            }
            TransportState::KeyExchange => {
                self.process_kex(data).await
            }
            TransportState::Authentication => {
                self.process_auth(data).await
            }
            TransportState::Ready => {
                Ok(None)
            }
        }
    }

    fn process_version_exchange(&mut self) -> Result<Option<Bytes>> {
        let buf_data = self.read_buffer.to_vec();

        for (idx, window) in buf_data.windows(4).enumerate() {
            if window == b"SSH-" {
                if let Some(client_version) = self.extract_ident_from(idx)? {
                    info!(version = %client_version, "Client version received");
                    self.client_version = Some(client_version.clone());

                    // Initialize KEX handler WITH HOST KEY
                    self.kex_handler = Some(KexHandler::new(
                        client_version,
                        SSH_VERSION.to_string(),
                        Arc::clone(&self.host_key),  // PASS HOST KEY HERE
                    ));

                    self.state = TransportState::KeyExchange;
                    return Ok(Some(Self::generate_server_ident()));
                }
            }
        }

        if self.is_http_garbage(&buf_data) {
            let len = buf_data.len();
            self.garbage_bytes += len;
            self.read_buffer.clear();

            if self.garbage_bytes > MAX_HANDSHAKE_GARBAGE {
                bail!("Exceeded max handshake garbage bytes");
            }

            debug!(garbage_bytes = len, "Ignoring HTTP/garbage");
            return Ok(None);
        }

        if self.read_buffer.len() > MAX_HANDSHAKE_GARBAGE {
            bail!("Handshake buffer exceeded");
        }

        Ok(None)
    }

    async fn process_kex(&mut self, data: &[u8]) -> Result<Option<Bytes>> {
        if data.is_empty() {
            return Ok(None);
        }

        let msg_type = data[0];
        debug!("KEX message type: {}", msg_type);

        if let Some(ref mut kex) = self.kex_handler {
            let response = kex.process_kex_message(msg_type, &data[1..]).await?;

            // Enable encryption after KEX completes
            if kex.is_complete() && !self.encryption_enabled {
                info!("KEX complete - enabling encryption");

                let algs = kex.algorithms()
                    .ok_or_else(|| anyhow::anyhow!("No algorithms negotiated"))?;

                let keys = kex.derive_keys()?;

                self.codec.enable_encryption(
                    &algs.encryption_c2s,
                    &algs.encryption_s2c,
                    &algs.mac_c2s,
                    &algs.mac_s2c,
                    &keys.key_client_to_server,
                    &keys.iv_client_to_server,
                    &keys.mac_client_to_server,
                    &keys.key_server_to_client,
                    &keys.iv_server_to_client,
                    &keys.mac_server_to_client,
                )?;

                self.encryption_enabled = true;
                info!("🔐 Encryption enabled: {} / {}", algs.encryption_c2s, algs.encryption_s2c);

                self.auth_handler = Some(TransportAuthHandler::new(
                    Arc::clone(&self.auth_cache)
                ));

                self.state = TransportState::Authentication;
            }

            Ok(response)
        } else {
            error!("KEX handler not initialized");
            bail!("KEX handler not initialized")
        }
    }

    async fn process_auth(&mut self, data: &[u8]) -> Result<Option<Bytes>> {
        if data.is_empty() {
            return Ok(None);
        }

        let (msg_type, payload) = self.decode_message(data)?;
        debug!("Auth message type: {} (encrypted)", msg_type);

        if let Some(ref mut auth) = self.auth_handler {
            let (response_payload, success) = auth.process_auth_message(msg_type, &payload).await?;

            if success {
                info!("✅ Authentication successful - ready for channels");
                self.state = TransportState::Ready;
            }

            if let Some(resp) = response_payload {
                let msg_type = if success { 52 } else { 51 };
                let encoded = self.encode_message(msg_type, &resp)?;
                Ok(Some(encoded))
            } else {
                Ok(None)
            }
        } else {
            error!("Auth handler not initialized");
            bail!("Auth handler not initialized")
        }
    }

    pub fn encode_message(&self, msg_type: u8, payload: &[u8]) -> Result<Bytes> {
        if self.encryption_enabled {
            self.codec.encode_packet(msg_type, payload)
        } else {
            let mut buf = BytesMut::with_capacity(1 + payload.len());
            buf.put_u8(msg_type);
            buf.put_slice(payload);
            Ok(buf.freeze())
        }
    }

    pub fn decode_message(&self, data: &[u8]) -> Result<(u8, Bytes)> {
        if self.encryption_enabled {
            self.codec.decode_packet(data)
        } else {
            if data.is_empty() {
                bail!("Empty message");
            }
            let msg_type = data[0];
            let payload = Bytes::copy_from_slice(&data[1..]);
            Ok((msg_type, payload))
        }
    }

    fn extract_ident_from(&mut self, start: usize) -> Result<Option<String>> {
        let buf = &self.read_buffer[start..];

        if let Some(newline_pos) = buf.iter().position(|&b| b == b'\n' || b == b'\r') {
            let ident_line = &buf[..newline_pos];

            if ident_line.starts_with(b"SSH-2.0-") || ident_line.starts_with(b"SSH-1.99-") {
                let version = String::from_utf8_lossy(ident_line).to_string();
                let consume_len = start + newline_pos + 1;
                self.read_buffer.advance(consume_len);
                return Ok(Some(version));
            } else {
                bail!("Invalid SSH version string");
            }
        }

        Ok(None)
    }

    fn is_http_garbage(&self, data: &[u8]) -> bool {
        const HTTP_PATTERNS: &[&[u8]] = &[
            b"GET ", b"POST ", b"PUT ", b"DELETE ",
            b"HEAD ", b"OPTIONS ", b"HTTP/",
            b"Host:", b"User-Agent:", b"Accept:",
        ];

        for pattern in HTTP_PATTERNS {
            if data.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }

        false
    }

    pub fn generate_server_ident() -> Bytes {
        let mut ident = BytesMut::new();
        ident.put_slice(SSH_VERSION.as_bytes());
        ident.put_slice(b"\r\n");
        ident.freeze()
    }

    pub fn cleanup(&mut self) {
        if let Some(ref auth) = self.auth_handler {
            auth.record_logout();
        }
    }
}

impl Drop for SshTransport {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[allow(dead_code)]
pub mod message_types {
    pub const SSH_MSG_DISCONNECT: u8 = 1;
    pub const SSH_MSG_IGNORE: u8 = 2;
    pub const SSH_MSG_DEBUG: u8 = 4;
    pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
    pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
    pub const SSH_MSG_KEXINIT: u8 = 20;
    pub const SSH_MSG_NEWKEYS: u8 = 21;
    pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
    pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
    pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
    pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
    pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
}