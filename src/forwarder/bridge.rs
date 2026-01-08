/// Bidirectional Forwarding Bridge
/// High-performance SSH ↔ TCP forwarding without per-byte tracking overhead

use anyhow::Result;
use bytes::{BytesMut, BufMut};
use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
use monoio::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info, error, warn};

use crate::ssh::window::WindowController;
use crate::pool::BufferPool;
use super::buffer::AdaptiveBufferManager;

/// SSH channel message types
const SSH_MSG_CHANNEL_DATA: u8 = 94;
const SSH_MSG_CHANNEL_EOF: u8 = 96;
const SSH_MSG_CHANNEL_CLOSE: u8 = 97;

/// Manages bidirectional forwarding between SSH channel and TCP target
pub struct BidirectionalBridge {
    local_channel_id: u32,
    remote_channel_id: u32,

    // Connection state
    target_addr: String,
    target_stream: Option<TcpStream>,

    // Buffers and memory management
    buffer_pool: Arc<BufferPool>,
    buffer_manager: AdaptiveBufferManager,

    // Flow control
    window_controller: WindowController,

    // EOF tracking for graceful close
    ssh_close_received: Arc<AtomicBool>,
    target_closed: Arc<AtomicBool>,
    ssh_eof_sent: Arc<AtomicBool>,
    target_eof_received: Arc<AtomicBool>,
}

impl BidirectionalBridge {
    pub fn new(
        local_channel_id: u32,
        remote_channel_id: u32,
        target_host: String,
        target_port: u32,
        buffer_pool: Arc<BufferPool>,
        initial_window: u32,
    ) -> Self {
        let target_addr = format!("{}:{}", target_host, target_port);

        Self {
            local_channel_id,
            remote_channel_id,
            target_addr,
            target_stream: None,
            buffer_pool,
            buffer_manager: AdaptiveBufferManager::new(1_000_000),
            window_controller: WindowController::new(initial_window, 50),
            ssh_close_received: Arc::new(AtomicBool::new(false)),
            target_closed: Arc::new(AtomicBool::new(false)),
            ssh_eof_sent: Arc::new(AtomicBool::new(false)),
            target_eof_received: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Initialize connection to target TCP server
    pub async fn connect_target(&mut self) -> Result<()> {
        info!(
            channel = self.local_channel_id,
            target = %self.target_addr,
            "Connecting to target"
        );

        match TcpStream::connect(&self.target_addr).await {
            Ok(stream) => {
                self.target_stream = Some(stream);
                info!(
                    channel = self.local_channel_id,
                    target = %self.target_addr,
                    "Connected"
                );
                Ok(())
            }
            Err(e) => {
                error!(
                    channel = self.local_channel_id,
                    target = %self.target_addr,
                    error = ?e,
                    "Connection failed"
                );
                self.target_closed.store(true, Ordering::Release);
                Err(e.into())
            }
        }
    }

    /// Forward data from SSH channel to target TCP
    pub async fn forward_ssh_to_target(&mut self, ssh_data: &[u8]) -> Result<()> {
        if self.target_stream.is_none() {
            warn!(channel = self.local_channel_id, "Target not connected");
            return Ok(());
        }

        let data_vec = ssh_data.to_vec();
        let bytes_len = data_vec.len();
        let target = self.target_stream.as_mut().unwrap();

        match target.write_all(data_vec).await {
            (Ok(_), _) => {
                debug!(
                channel = self.local_channel_id,
                bytes = bytes_len,
                "→ Target"
            );

                // ADDED: Track transfer for adaptive buffering
                self.buffer_manager.record_transfer(bytes_len as u32);

                // ADDED: Check if buffer mode should switch (only every 5 seconds)
                if let Some(new_mode) = self.buffer_manager.should_switch_mode() {
                    info!(
                    channel = self.local_channel_id,
                    mode = ?new_mode,
                    "Switched buffer mode"
                );
                }

                Ok(())
            }
            (Err(e), _) => {
                error!(
                channel = self.local_channel_id,
                error = ?e,
                "Write failed"
            );
                self.target_closed.store(true, Ordering::Release);
                Err(e.into())
            }
        }
    }


    /// Read from target TCP and prepare SSH channel data message
    pub async fn read_from_target(&mut self) -> Result<Option<BytesMut>> {
        if self.target_stream.is_none() {
            return Ok(None);
        }

        let buffer_mode = self.buffer_manager.current_mode();
        let buf = if buffer_mode == super::buffer::BufferMode::Standard {
            self.buffer_pool.get_standard()
        } else {
            self.buffer_pool.get_high_throughput()
        };

        let mut bytes_mut = buf.buffer;
        let target = self.target_stream.as_mut().unwrap();

        let (result, returned_buf) = target.read(bytes_mut).await;
        bytes_mut = returned_buf;

        match result {
            Ok(0) => {
                debug!(channel = self.local_channel_id, "Target EOF");
                self.target_eof_received.store(true, Ordering::Release);

                self.buffer_pool.return_buffer(
                    bytes_mut,
                    buffer_mode == super::buffer::BufferMode::HighThroughput
                );
                Ok(None)
            }
            Ok(n) => {
                let data = bytes_mut[..n].to_vec();

                debug!(
                channel = self.local_channel_id,
                bytes = n,
                "← Target"
            );

                // Check SSH window space
                if !self.window_controller.has_space(n as u32) {
                    warn!(
                    channel = self.local_channel_id,
                    bytes = n,
                    "Insufficient window space"
                );
                }

                self.window_controller.consume(n as u32)?;

                let msg = self.build_channel_data(&data);

                if let Some(refill_bytes) = self.window_controller.check_refill() {
                    debug!(
                    channel = self.local_channel_id,
                    refill = refill_bytes,
                    "Window refilled"
                );
                }

                // ADDED: Track transfer for adaptive buffering
                self.buffer_manager.record_transfer(n as u32);

                // ADDED: Check if buffer mode should switch
                if let Some(new_mode) = self.buffer_manager.should_switch_mode() {
                    info!(
                    channel = self.local_channel_id,
                    mode = ?new_mode,
                    "Switched buffer mode"
                );
                }

                self.buffer_pool.return_buffer(
                    bytes_mut,
                    buffer_mode == super::buffer::BufferMode::HighThroughput
                );

                Ok(Some(msg))
            }
            Err(e) => {
                error!(
                channel = self.local_channel_id,
                error = ?e,
                "Read error"
            );
                self.target_closed.store(true, Ordering::Release);

                self.buffer_pool.return_buffer(
                    bytes_mut,
                    buffer_mode == super::buffer::BufferMode::HighThroughput
                );

                Err(e.into())
            }
        }
    }

    /// Handle SSH_MSG_CHANNEL_EOF from client
    pub async fn handle_ssh_close(&mut self) -> Result<()> {
        debug!(channel = self.local_channel_id, "SSH close requested");
        self.ssh_close_received.store(true, Ordering::Release);
        Ok(())
    }

    /// Build SSH_MSG_CHANNEL_DATA message
    fn build_channel_data(&self, data: &[u8]) -> BytesMut {
        let mut msg = BytesMut::new();
        msg.put_u8(SSH_MSG_CHANNEL_DATA);
        msg.put_u32(self.remote_channel_id);
        msg.put_u32(data.len() as u32);
        msg.put_slice(data);
        msg
    }

    /// Build SSH_MSG_CHANNEL_EOF message
    pub fn build_channel_eof(&self) -> BytesMut {
        let mut msg = BytesMut::new();
        msg.put_u8(SSH_MSG_CHANNEL_EOF);
        msg.put_u32(self.remote_channel_id);
        msg
    }

    /// Build SSH_MSG_CHANNEL_CLOSE message
    pub fn build_channel_close(&self) -> BytesMut {
        let mut msg = BytesMut::new();
        msg.put_u8(SSH_MSG_CHANNEL_CLOSE);
        msg.put_u32(self.remote_channel_id);
        msg
    }

    /// Check if SSH has sent EOF
    pub fn ssh_eof_sent(&self) -> bool {
        self.ssh_eof_sent.load(Ordering::Acquire)
    }

    /// Mark SSH EOF as sent
    pub fn mark_ssh_eof_sent(&self) {
        self.ssh_eof_sent.store(true, Ordering::Release);
    }

    /// Check if target has closed
    pub fn target_closed(&self) -> bool {
        self.target_closed.load(Ordering::Acquire) ||
            self.target_eof_received.load(Ordering::Acquire)
    }

    /// Check if connection is fully closed both ways
    pub fn is_fully_closed(&self) -> bool {
        (self.ssh_close_received.load(Ordering::Acquire) ||
            self.ssh_eof_sent.load(Ordering::Acquire)) &&
            (self.target_closed.load(Ordering::Acquire) ||
                self.target_eof_received.load(Ordering::Acquire))
    }

    /// Get current SSH window size
    pub fn window_size(&self) -> u32 {
        self.window_controller.current_size()
    }
}