/// SSH Handler - High-level coordinator with host key support

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use std::sync::Arc;
use tracing::{debug, info};

use crate::auth::AuthCache;
use crate::config::Settings;
use crate::ssh::keys::HostKey;  // ADD THIS
use crate::ssh::transport::transport::{SshTransport, TransportState};
use super::channel_handler::ChannelHandler;

pub struct SshHandler {
    transport: SshTransport,
    channel_handler: ChannelHandler,
    settings: Settings,
}

impl SshHandler {
    pub fn new(
        settings: Settings,
        auth_cache: Arc<AuthCache>,
        host_key: Arc<HostKey>,  // ADD THIS PARAMETER
    ) -> Self {
        Self {
            transport: SshTransport::new(
                Arc::clone(&auth_cache),
                host_key,  // PASS TO TRANSPORT
            ),
            channel_handler: ChannelHandler::new(settings.clone()),
            settings,
        }
    }

    pub async fn process_data(&mut self, data: &[u8]) -> Result<Option<Bytes>> {
        match self.transport.state() {
            TransportState::WaitingIdent |
            TransportState::KeyExchange |
            TransportState::Authentication => {
                let response = self.transport.process_transport_data(data).await?;

                if self.transport.is_ready() && !self.channel_handler_authenticated() {
                    self.channel_handler.set_authenticated(true);
                    info!("Channel handler ready");
                }

                Ok(response)
            }

            TransportState::Ready => {
                // Buffer data and process complete packets
                self.transport.append_to_buffer(data);
                self.process_buffered_channel_messages().await
            }
        }
    }

    /// Process buffered channel messages (handles partial packets)
    async fn process_buffered_channel_messages(&mut self) -> Result<Option<Bytes>> {
        let mut combined_response: Option<Bytes> = None;

        // Process all complete packets in buffer
        loop {
            match self.transport.decode_next_packet()? {
                Some((msg_type, payload)) => {
                    debug!("Channel message type: {} (decrypted)", msg_type);
                    let response = self.process_single_channel_message(msg_type, payload).await?;
                    
                    // Combine responses if we have multiple
                    if let Some(resp) = response {
                        if let Some(existing) = combined_response {
                            let mut combined = BytesMut::new();
                            combined.extend_from_slice(&existing);
                            combined.extend_from_slice(&resp);
                            combined_response = Some(combined.freeze());
                        } else {
                            combined_response = Some(resp);
                        }
                    }
                }
                None => {
                    // No complete packet available, need more data
                    break;
                }
            }
        }

        Ok(combined_response)
    }

    /// Process a single decoded channel message
    async fn process_single_channel_message(&mut self, msg_type: u8, payload: Bytes) -> Result<Option<Bytes>> {

        use crate::ssh::transport::transport::message_types::*;

        let (response_msg_type, response_payload) = match msg_type {
            SSH_MSG_CHANNEL_OPEN => {
                // Response is SSH_MSG_CHANNEL_OPEN_CONFIRMATION (91)
                if let Some(payload) = self.channel_handler.handle_channel_open(payload).await? {
                    (91, payload)
                } else {
                    return Ok(None);
                }
            }
            SSH_MSG_CHANNEL_DATA => {
                // Response might be SSH_MSG_CHANNEL_WINDOW_ADJUST (93) or None
                if let Some(payload) = self.channel_handler.handle_channel_data(payload).await? {
                    (93, payload) // Window adjust
                } else {
                    return Ok(None);
                }
            }
            96 => { // SSH_MSG_CHANNEL_EOF
                // No response for EOF
                self.channel_handler.handle_channel_eof(payload)?;
                return Ok(None);
            }
            SSH_MSG_CHANNEL_CLOSE => {
                // Response is SSH_MSG_CHANNEL_CLOSE (97) - echo back
                if let Some(payload) = self.channel_handler.handle_channel_close(payload)? {
                    (97, payload)
                } else {
                    return Ok(None);
                }
            }
            93 => { // SSH_MSG_CHANNEL_WINDOW_ADJUST
                // No response for window adjust
                self.channel_handler.handle_window_adjust(payload)?;
                return Ok(None);
            }
            98 => { // SSH_MSG_CHANNEL_REQUEST
                // Response is SSH_MSG_CHANNEL_FAILURE (100) or SSH_MSG_CHANNEL_SUCCESS (99)
                // For now, we reject all requests, so return failure
                if let Some(payload) = self.channel_handler.handle_channel_request(payload)? {
                    (100, payload) // Channel failure
                } else {
                    return Ok(None);
                }
            }
            SSH_MSG_IGNORE | SSH_MSG_DEBUG => {
                debug!("Ignoring message type: {}", msg_type);
                return Ok(None);
            }
            _ => {
                debug!("Unsupported message type: {}", msg_type);
                return Ok(None);
            }
        };

        // Encode response through transport layer (adds message type and encryption)
        let encoded = self.transport.encode_message(response_msg_type, &response_payload)?;
        Ok(Some(encoded))
    }

    pub fn is_authenticated(&self) -> bool {
        self.transport.is_authenticated()
    }

    pub fn username(&self) -> Option<&str> {
        self.transport.username()
    }

    pub fn channel_handler_mut(&mut self) -> &mut ChannelHandler {
        &mut self.channel_handler
    }

    pub fn transport(&self) -> &SshTransport {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut SshTransport {
        &mut self.transport
    }

    fn channel_handler_authenticated(&self) -> bool {
        true
    }

    pub fn cleanup(&mut self) {
        self.channel_handler.close_all();
    }
}

impl Drop for SshHandler {
    fn drop(&mut self) {
        self.cleanup();
    }
}