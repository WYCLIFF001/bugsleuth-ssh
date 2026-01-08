use anyhow::{Result, bail};
use bytes::{Bytes, BytesMut, BufMut};
use tracing::{debug, info, warn};
use std::collections::HashMap;

use crate::config::Settings;
use crate::ssh::channel::{ChannelManager, Channel};
use crate::ssh::protocol;
use crate::ssh::protocol::ChannelOpenRequest;

/// Pending forwarding connection state
#[derive(Debug, Clone)]
pub struct PendingForward {
    pub local_channel_id: u32,
    pub remote_channel_id: u32,
    pub target_host: String,
    pub target_port: u32,
}

/// Pending channel data to forward
#[derive(Debug, Clone)]
pub struct PendingChannelData {
    pub channel_id: u32,
    pub data: Vec<u8>,
}

/// SSH channel handler
pub struct ChannelHandler {
    channels: ChannelManager,
    settings: Settings,
    authenticated: bool,
    // Track channels that need forwarding setup
    pending_forwards: HashMap<u32, PendingForward>,
    // Track channel data that needs to be forwarded to TCP targets
    pending_data: Vec<PendingChannelData>,
}

impl ChannelHandler {
    pub fn new(settings: Settings) -> Self {
        Self {
            channels: ChannelManager::new(),
            settings,
            authenticated: false,
            pending_forwards: HashMap::new(),
            pending_data: Vec::new(),
        }
    }

    pub fn set_authenticated(&mut self, authenticated: bool) {
        self.authenticated = authenticated;
    }

    /// Handle channel open
    /// PRODUCTION: Try connecting to target BEFORE confirming channel (like russh)
    pub async fn handle_channel_open(&mut self, payload: Bytes) -> Result<Option<Bytes>> {
        if !self.authenticated {
            warn!("Channel open before authentication");
            bail!("Not authenticated");
        }

        let open_req = ChannelOpenRequest::parse(&payload)?;

        if !open_req.is_supported() {
            warn!("Unsupported channel type: {}", open_req.channel_type);
            let response = protocol::build_channel_open_failure(
                open_req.sender_channel,
                protocol::open_failure::UNKNOWN_CHANNEL_TYPE,
                "Only direct-tcpip is supported"
            );
            return Ok(Some(response));
        }

        let target_host = open_req.host.clone().unwrap_or_else(|| "unknown".to_string());
        let target_port = open_req.port.unwrap_or(0);
        let target_addr = format!("{}:{}", target_host, target_port);

        // PRODUCTION FIX: Try connecting to target BEFORE confirming channel
        // This ensures we can actually reach the target before telling the client it's ready
        info!(
            "Attempting connection to target: {}:{} (channel={})",
            target_host,
            target_port,
            open_req.sender_channel
        );

        // Attempt connection with timeout
        let connect_result = monoio::time::timeout(
            self.settings.target_connect_timeout,
            monoio::net::TcpStream::connect(&target_addr)
        ).await;

        let target_connected = match connect_result {
            Ok(Ok(_)) => {
                info!(
                    "Successfully connected to target: {}:{}",
                    target_host, target_port
                );
                true
            }
            Ok(Err(e)) => {
                warn!(
                    "Connection to {}:{} failed: {}",
                    target_host, target_port, e
                );
                false
            }
            Err(_) => {
                warn!(
                    "Connection to {}:{} timed out after {:?}",
                    target_host, target_port, self.settings.target_connect_timeout
                );
                false
            }
        };

        // If connection failed, send failure message
        if !target_connected {
            let response = protocol::build_channel_open_failure(
                open_req.sender_channel,
                protocol::open_failure::CONNECT_FAILED,
                &format!("Failed to connect to {}:{}", target_host, target_port)
            );
            return Ok(Some(response));
        }

        // Connection successful - proceed with channel setup
        let local_id = self.channels.allocate_channel_id();
        let mut channel = Channel::new(
            local_id,
            open_req.sender_channel,
            self.settings.initial_window_size,
            self.settings.max_packet_size,
        );

        channel.target_host = Some(target_host.clone());
        channel.target_port = Some(target_port);

        info!(
            "Channel opened: local={}, remote={}, target={}:{}",
            local_id,
            open_req.sender_channel,
            target_host,
            target_port
        );

        // Store pending forward info (connection already verified)
        self.pending_forwards.insert(local_id, PendingForward {
            local_channel_id: local_id,
            remote_channel_id: open_req.sender_channel,
            target_host: target_host.clone(),
            target_port,
        });

        self.channels.add_channel(channel);

        // Send confirmation only after successful connection
        let response = protocol::build_channel_open_confirmation(
            open_req.sender_channel,
            local_id,
            self.settings.initial_window_size,
            self.settings.max_packet_size,
        );

        Ok(Some(response))
    }

    /// Handle channel data - forward to target
    pub async fn handle_channel_data(&mut self, payload: Bytes) -> Result<Option<Bytes>> {
        if payload.len() < 8 {
            bail!("Invalid channel data message");
        }

        let recipient_channel = u32::from_be_bytes([
            payload[0], payload[1], payload[2], payload[3]
        ]);
        let data_len = u32::from_be_bytes([
            payload[4], payload[5], payload[6], payload[7]
        ]) as usize;

        if payload.len() < 8 + data_len {
            bail!("Incomplete channel data");
        }

        let data = payload[8..8 + data_len].to_vec();

        debug!(
            "Channel data: channel={}, bytes={}",
            recipient_channel,
            data_len
        );

        // Store data for forwarding to TCP target
        self.pending_data.push(PendingChannelData {
            channel_id: recipient_channel,
            data: data.clone(),
        });

        // Check if we need window adjust BEFORE borrowing mutably again
        let (should_send_adjust, remote_id) = if let Some(channel) = self.channels.get_channel_mut(recipient_channel) {
            channel.consume_local_window(data_len as u32)?;

            debug!(
                "Data queued for forwarding: channel={}, target={}:{}, bytes={}",
                recipient_channel,
                channel.target_host.as_deref().unwrap_or("unknown"),
                channel.target_port.unwrap_or(0),
                data_len
            );

            let should_adjust = channel.local_window < (self.settings.initial_window_size / 2);
            (should_adjust, channel.remote_id)
        } else {
            warn!("Data for unknown channel: {}", recipient_channel);
            return Ok(None);
        };

        // Now safely build window adjust without borrow conflict
        if should_send_adjust {
            let channel = self.channels.get_channel_mut(recipient_channel).unwrap();
            let bytes_to_add = self.settings.initial_window_size - channel.local_window;
            channel.local_window = self.settings.initial_window_size;

            debug!(
                "Sending window adjust: channel={}, bytes={}",
                recipient_channel,
                bytes_to_add
            );

            return Ok(Some(self.build_window_adjust(remote_id, bytes_to_add)?));
        }

        Ok(None)
    }

    /// Handle channel EOF
    pub fn handle_channel_eof(&mut self, payload: Bytes) -> Result<Option<Bytes>> {
        if payload.len() < 4 {
            bail!("Invalid channel EOF");
        }

        let channel_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

        if let Some(channel) = self.channels.get_channel_mut(channel_id) {
            debug!("Channel EOF: {}", channel_id);
            channel.set_remote_eof();

            info!("SSH client EOF signaled for channel: {}, forwarding to target", channel_id);
        }

        Ok(None)
    }

    /// Handle channel close
    pub fn handle_channel_close(&mut self, payload: Bytes) -> Result<Option<Bytes>> {
        if payload.len() < 4 {
            bail!("Invalid channel close");
        }

        let channel_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

        if let Some(mut channel) = self.channels.remove_channel(channel_id) {
            info!("Channel closed: {}", channel_id);
            channel.close();

            // Remove pending forward
            self.pending_forwards.remove(&channel_id);

            // Build close response
            let mut response = BytesMut::new();
            response.put_u32(channel.remote_id);

            return Ok(Some(response.freeze()));
        }

        Ok(None)
    }

    /// Handle window adjust
    pub fn handle_window_adjust(&mut self, payload: Bytes) -> Result<Option<Bytes>> {
        if payload.len() < 8 {
            bail!("Invalid window adjust");
        }

        let channel_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let bytes_to_add = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);

        if let Some(channel) = self.channels.get_channel_mut(channel_id) {
            debug!("Window adjust: channel={}, bytes={}", channel_id, bytes_to_add);
            channel.add_remote_window(bytes_to_add);
        }

        Ok(None)
    }

    /// Handle channel request (pty-req, shell, etc - we reject these)
    pub fn handle_channel_request(&mut self, payload: Bytes) -> Result<Option<Bytes>> {
        if payload.len() < 4 {
            bail!("Invalid channel request");
        }

        let channel_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

        debug!("Channel request for channel {} (rejecting - not supported)", channel_id);

        // Send failure response
        let mut response = BytesMut::new();
        response.put_u32(channel_id);

        Ok(Some(response.freeze()))
    }

    /// Build channel data message for sending data from target to SSH
    pub fn build_channel_data(&self, channel_id: u32, data: &[u8]) -> Result<Bytes> {
        if let Some(channel) = self.channels.get_channel(channel_id) {
            let mut msg = BytesMut::new();
            msg.put_u32(channel.remote_id);
            msg.put_u32(data.len() as u32);
            msg.put_slice(data);
            Ok(msg.freeze())
        } else {
            bail!("Channel not found: {}", channel_id);
        }
    }

    /// Build channel EOF message
    pub fn build_channel_eof(&self, channel_id: u32) -> Result<Bytes> {
        if let Some(channel) = self.channels.get_channel(channel_id) {
            let mut msg = BytesMut::new();
            msg.put_u32(channel.remote_id);
            Ok(msg.freeze())
        } else {
            bail!("Channel not found: {}", channel_id);
        }
    }

    /// Build window adjust message
    fn build_window_adjust(&self, remote_channel_id: u32, bytes_to_add: u32) -> Result<Bytes> {
        let mut msg = BytesMut::new();
        msg.put_u32(remote_channel_id);
        msg.put_u32(bytes_to_add);
        Ok(msg.freeze())
    }

    /// Close all channels
    pub fn close_all(&mut self) {
        self.channels.close_all();
        self.pending_forwards.clear();
    }

    /// Get channel manager reference
    pub fn channels(&self) -> &ChannelManager {
        &self.channels
    }

    /// Get channel manager mutable reference
    pub fn channels_mut(&mut self) -> &mut ChannelManager {
        &mut self.channels
    }

    /// Get pending forwards for setting up TCP connections
    pub fn take_pending_forwards(&mut self) -> Vec<PendingForward> {
        self.pending_forwards.drain().map(|(_, v)| v).collect()
    }

    /// Check if channel can send data
    pub fn can_send(&self, channel_id: u32) -> bool {
        self.channels.get_channel(channel_id)
            .map(|ch| ch.can_send())
            .unwrap_or(false)
    }

    /// Get pending channel data that needs to be forwarded to TCP targets
    pub fn take_pending_data(&mut self) -> Vec<PendingChannelData> {
        std::mem::take(&mut self.pending_data)
    }

    /// Extract channel data payload for forwarding
    pub fn extract_channel_data(&self, payload: &Bytes) -> Result<(u32, Vec<u8>)> {
        if payload.len() < 8 {
            bail!("Invalid channel data message");
        }

        let recipient_channel = u32::from_be_bytes([
            payload[0], payload[1], payload[2], payload[3]
        ]);
        let data_len = u32::from_be_bytes([
            payload[4], payload[5], payload[6], payload[7]
        ]) as usize;

        if payload.len() < 8 + data_len {
            bail!("Incomplete channel data");
        }

        let data = payload[8..8 + data_len].to_vec();

        Ok((recipient_channel, data))
    }
}