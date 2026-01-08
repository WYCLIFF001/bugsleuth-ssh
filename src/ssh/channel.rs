use std::collections::HashMap;
use anyhow::{Result, bail};
use tracing::{debug};

/// SSH channel state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// Channel open and active
    Open,
    /// Received EOF from remote
    RemoteEof,
    /// Sent EOF to remote
    LocalEof,
    /// Both sides sent EOF
    EofBoth,
    /// Channel closed
    Closed,
}

/// SSH channel information
#[derive(Debug)]
pub struct Channel {
    /// Our channel ID
    pub local_id: u32,
    /// Remote channel ID
    pub remote_id: u32,
    /// Current state
    pub state: ChannelState,
    /// Remote window size (how much we can send)
    pub remote_window: u32,
    /// Our window size (how much remote can send)
    pub local_window: u32,
    /// Maximum packet size remote will accept
    pub remote_max_packet: u32,
    /// Maximum packet size we accept
    pub local_max_packet: u32,
    /// Target host (for direct-tcpip)
    pub target_host: Option<String>,
    /// Target port (for direct-tcpip)
    pub target_port: Option<u32>,
}

impl Channel {
    pub fn new(
        local_id: u32,
        remote_id: u32,
        initial_window: u32,
        max_packet_size: u32,
    ) -> Self {
        Self {
            local_id,
            remote_id,
            state: ChannelState::Open,
            remote_window: initial_window,
            local_window: initial_window,
            remote_max_packet: max_packet_size,
            local_max_packet: max_packet_size,
            target_host: None,
            target_port: None,
        }
    }

    /// Check if channel can send data
    pub fn can_send(&self) -> bool {
        self.state == ChannelState::Open && self.remote_window > 0
    }

    /// Check if channel can receive data
    pub fn can_receive(&self) -> bool {
        matches!(self.state, ChannelState::Open | ChannelState::RemoteEof)
    }

    /// Consume remote window for sending
    pub fn consume_window(&mut self, bytes: u32) -> Result<()> {
        if bytes > self.remote_window {
            bail!("Insufficient remote window");
        }
        self.remote_window -= bytes;
        Ok(())
    }

    /// Add to remote window (from window adjust)
    pub fn add_remote_window(&mut self, bytes: u32) {
        self.remote_window = self.remote_window.saturating_add(bytes);
    }

    /// Consume local window (data received)
    pub fn consume_local_window(&mut self, bytes: u32) -> Result<()> {
        if bytes > self.local_window {
            bail!("Insufficient local window");
        }
        self.local_window -= bytes;
        Ok(())
    }

    /// Mark remote EOF received
    pub fn set_remote_eof(&mut self) {
        self.state = match self.state {
            ChannelState::Open => ChannelState::RemoteEof,
            ChannelState::LocalEof => ChannelState::EofBoth,
            other => other,
        };
    }

    /// Mark local EOF sent
    pub fn set_local_eof(&mut self) {
        self.state = match self.state {
            ChannelState::Open => ChannelState::LocalEof,
            ChannelState::RemoteEof => ChannelState::EofBoth,
            other => other,
        };
    }

    /// Close channel
    pub fn close(&mut self) {
        self.state = ChannelState::Closed;
    }
}

/// Manage all SSH channels for a connection
pub struct ChannelManager {
    channels: HashMap<u32, Channel>,
    next_channel_id: u32,
}

impl ChannelManager {
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            next_channel_id: 0,
        }
    }

    /// Allocate a new channel ID
    pub fn allocate_channel_id(&mut self) -> u32 {
        let id = self.next_channel_id;
        self.next_channel_id = self.next_channel_id.wrapping_add(1);
        id
    }

    /// Add a new channel
    pub fn add_channel(&mut self, channel: Channel) {
        debug!(
            local_id = channel.local_id,
            remote_id = channel.remote_id,
            "Channel opened"
        );
        self.channels.insert(channel.local_id, channel);
    }

    /// Get channel by local ID
    pub fn get_channel(&self, local_id: u32) -> Option<&Channel> {
        self.channels.get(&local_id)
    }

    /// Get mutable channel by local ID
    pub fn get_channel_mut(&mut self, local_id: u32) -> Option<&mut Channel> {
        self.channels.get_mut(&local_id)
    }

    /// Remove and return channel
    pub fn remove_channel(&mut self, local_id: u32) -> Option<Channel> {
        let channel = self.channels.remove(&local_id);
        if let Some(ref ch) = channel {
            debug!(
                local_id = ch.local_id,
                remote_id = ch.remote_id,
                "Channel removed"
            );
        }
        channel
    }

    /// Get all channel IDs
    pub fn channel_ids(&self) -> Vec<u32> {
        self.channels.keys().copied().collect()
    }

    /// Get number of active channels
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Close all channels
    pub fn close_all(&mut self) {
        for channel in self.channels.values_mut() {
            channel.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_window() {
        let mut channel = Channel::new(1, 100, 1000, 32768);

        assert!(channel.can_send());
        channel.consume_window(500).unwrap();
        assert_eq!(channel.remote_window, 500);

        channel.add_remote_window(300);
        assert_eq!(channel.remote_window, 800);
    }

    #[test]
    fn test_channel_eof() {
        let mut channel = Channel::new(1, 100, 1000, 32768);

        channel.set_remote_eof();
        assert_eq!(channel.state, ChannelState::RemoteEof);

        channel.set_local_eof();
        assert_eq!(channel.state, ChannelState::EofBoth);
    }

    #[test]
    fn test_channel_manager() {
        let mut mgr = ChannelManager::new();

        let id1 = mgr.allocate_channel_id();
        let id2 = mgr.allocate_channel_id();

        assert_eq!(id1, 0);
        assert_eq!(id2, 1);

        let ch = Channel::new(id1, 100, 1000, 32768);
        mgr.add_channel(ch);

        assert_eq!(mgr.channel_count(), 1);
        assert!(mgr.get_channel(id1).is_some());
    }
}