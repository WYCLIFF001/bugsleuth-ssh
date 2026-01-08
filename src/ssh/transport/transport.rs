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
                // KEX messages are not encrypted, process directly
                self.process_kex(data).await
            }
            TransportState::Authentication => {
                // Auth messages are encrypted, need to buffer and decode
                self.read_buffer.put_slice(data);
                self.process_auth_buffered().await
            }
            TransportState::Ready => {
                // Channel messages are encrypted, buffer for decoding
                self.read_buffer.put_slice(data);
                Ok(None) // Will be processed by handler
            }
        }
    }

    /// Process buffered authentication data
    async fn process_auth_buffered(&mut self) -> Result<Option<Bytes>> {
        let mut responses = Vec::new();
        
        // Try to decode complete packets from buffer
        while !self.read_buffer.is_empty() {
            // Check if we have enough data for packet length (4 bytes)
            if self.read_buffer.len() < 4 {
                break; // Need more data
            }

            let packet_length = u32::from_be_bytes([
                self.read_buffer[0],
                self.read_buffer[1],
                self.read_buffer[2],
                self.read_buffer[3],
            ]) as usize;

            // Check if we have the complete packet
            // For encrypted packets: 4 bytes length + packet_length + MAC
            let mac_size = if self.encryption_enabled {
                // MAC size depends on algorithm, typically 16-32 bytes
                // We'll use a conservative estimate and check
                32
            } else {
                0
            };

            let total_needed = 4 + packet_length + mac_size;
            if self.read_buffer.len() < total_needed {
                break; // Need more data
            }

            // Try to decode the packet
            match self.codec.decode_packet(&self.read_buffer) {
                Ok((msg_type, payload)) => {
                    // Successfully decoded, remove from buffer
                    let consumed = 4 + packet_length + mac_size;
                    if self.read_buffer.len() >= consumed {
                        self.read_buffer.advance(consumed);
                    } else {
                        // Fallback: clear buffer if we can't determine exact size
                        self.read_buffer.clear();
                    }

                    // Process the auth message
                    if let Some(ref mut auth) = self.auth_handler {
                        let (response_payload, success) = auth.process_auth_message(msg_type, &payload).await?;

                        if success {
                            info!("✅ Authentication successful - ready for channels");
                            self.state = TransportState::Ready;
                        }

                        if let Some(resp) = response_payload {
                            let msg_type = if success { 52 } else { 51 };
                            let encoded = self.encode_message(msg_type, &resp)?;
                            responses.push(encoded);
                        }
                    }
                }
                Err(e) => {
                    // If it's "incomplete packet", we need more data
                    if e.to_string().contains("Incomplete") || e.to_string().contains("too short") {
                        break;
                    }
                    // Otherwise, it's a real error - log and clear buffer
                    tracing::error!("Auth packet decode error: {:?}", e);
                    self.read_buffer.clear();
                    break;
                }
            }
        }

        if responses.is_empty() {
            Ok(None)
        } else if responses.len() == 1 {
            Ok(Some(responses.into_iter().next().unwrap()))
        } else {
            // Multiple responses - combine them (shouldn't happen in practice)
            let mut combined = BytesMut::new();
            for resp in responses {
                combined.extend_from_slice(&resp);
            }
            Ok(Some(combined.freeze()))
        }
    }

    /// Decode a complete packet from the read buffer (for Ready state)
    pub fn decode_next_packet(&mut self) -> Result<Option<(u8, Bytes)>> {
        if self.read_buffer.is_empty() {
            return Ok(None);
        }

        // Check if we have enough data for packet length (4 bytes)
        if self.read_buffer.len() < 4 {
            return Ok(None); // Need more data
        }

        let packet_length = u32::from_be_bytes([
            self.read_buffer[0],
            self.read_buffer[1],
            self.read_buffer[2],
            self.read_buffer[3],
        ]) as usize;

        // For encrypted packets, we need: 4 (length) + packet_length + MAC
        // MAC size depends on algorithm (HMAC-SHA256 = 32, HMAC-SHA1 = 20, ChaCha20-Poly1305 = 16)
        // We'll try to decode and see if it works, advancing buffer on success
        let min_needed = 4 + packet_length;
        if self.read_buffer.len() < min_needed {
            return Ok(None); // Need more data for at least the packet
        }

        // Try decoding with current buffer - decode_packet will tell us if incomplete
        let buffer_snapshot = self.read_buffer.clone();
        match self.codec.decode_packet(&buffer_snapshot) {
            Ok((msg_type, payload)) => {
                // Successfully decoded! Now figure out how much we consumed
                // We need to know the MAC size to advance correctly
                // For now, use a heuristic: try to find where next packet starts
                let consumed = if self.encryption_enabled {
                    // Encrypted: 4 (length) + encrypted_packet_length + MAC
                    // The encrypted packet length includes padding, so packet_length is the encrypted size
                    // MAC is appended after encryption
                    let mac_size = if self.codec.decrypt.as_ref()
                        .map(|c| c.mac_type().mac_size())
                        .unwrap_or(0) > 0 {
                        self.codec.decrypt.as_ref()
                            .map(|c| c.mac_type().mac_size())
                            .unwrap_or(32) // Default to 32 if unknown
                    } else {
                        0
                    };
                    4 + packet_length + mac_size
                } else {
                    // Unencrypted: just 4 + packet_length
                    4 + packet_length
                };

                // Only advance if we have that much data
                if consumed <= self.read_buffer.len() {
                    self.read_buffer.advance(consumed);
                } else {
                    // This shouldn't happen if decode succeeded, but handle it
                    tracing::warn!("Decode succeeded but consumed size {} > buffer size {}", 
                        consumed, self.read_buffer.len());
                    // Advance by minimum (shouldn't happen)
                    self.read_buffer.advance(min_needed);
                }

                Ok(Some((msg_type, payload)))
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("Incomplete") || err_str.contains("too short") || 
                   err_str.contains("Packet too short") {
                    Ok(None) // Need more data
                } else {
                    // Real decode error - might be corrupted data
                    // Try to recover by skipping this packet
                    tracing::warn!("Packet decode error: {:?}, attempting recovery", e);
                    // Skip at least the length field and try to find next packet
                    if self.read_buffer.len() >= 4 {
                        self.read_buffer.advance(4);
                    } else {
                        self.read_buffer.clear();
                    }
                    Ok(None) // Return None to continue processing
                }
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

    /// Append data to read buffer (for Ready state)
    pub fn append_to_buffer(&mut self, data: &[u8]) {
        self.read_buffer.put_slice(data);
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