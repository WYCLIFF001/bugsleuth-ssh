/// SSH Handler - High-level coordinator with host key support

use anyhow::Result;
use bytes::Bytes;
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
                self.process_channel_message(data).await
            }
        }
    }

    async fn process_channel_message(&mut self, data: &[u8]) -> Result<Option<Bytes>> {
        if data.is_empty() {
            return Ok(None);
        }

        let msg_type = data[0];
        let payload = Bytes::copy_from_slice(&data[1..]);

        debug!("Channel message type: {}", msg_type);

        use crate::ssh::transport::transport::message_types::*;

        match msg_type {
            SSH_MSG_CHANNEL_OPEN => {
                self.channel_handler.handle_channel_open(payload).await
            }
            SSH_MSG_CHANNEL_DATA => {
                self.channel_handler.handle_channel_data(payload).await
            }
            96 => {
                self.channel_handler.handle_channel_eof(payload)
            }
            SSH_MSG_CHANNEL_CLOSE => {
                self.channel_handler.handle_channel_close(payload)
            }
            93 => {
                self.channel_handler.handle_window_adjust(payload)
            }
            98 => {
                self.channel_handler.handle_channel_request(payload)
            }
            SSH_MSG_IGNORE | SSH_MSG_DEBUG => {
                debug!("Ignoring message type: {}", msg_type);
                Ok(None)
            }
            _ => {
                debug!("Unsupported message type: {}", msg_type);
                Ok(None)
            }
        }
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