/// Connection Manager - Pass host key through chain

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use tracing::{debug, info, error, warn};
use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
use monoio::net::UnixStream;

use crate::config::Settings;
use crate::auth::AuthCache;
use crate::ssh::handler::SshHandler;
use crate::ssh::keys::HostKey;  // ADD THIS
use crate::forwarder::bridge::BidirectionalBridge;
use crate::pool::BufferPool;
use crate::utils::guard::SessionGuard;

const SSH_MSG_CHANNEL_DATA: u8 = 94;
const SSH_MSG_CHANNEL_EOF: u8 = 96;
const SSH_MSG_CHANNEL_CLOSE: u8 = 97;

pub struct ConnectionManager {
    ssh_handler: SshHandler,
    bridges: HashMap<u32, BidirectionalBridge>,
    buffer_pool: Arc<BufferPool>,
    session_guard: Option<SessionGuard>,
    auth_cache: Arc<AuthCache>,
    initial_window_size: u32,
    authenticated: bool,
}

impl ConnectionManager {
    pub fn new(
        settings: Settings,
        auth_cache: Arc<AuthCache>,
        host_key: Arc<HostKey>,
    ) -> Self {
        let buffer_pool = BufferPool::new(
            settings.standard_buffer_size,
            settings.high_throughput_buffer_size,
        );

        // Create channel for bridge messages (bounded to prevent memory issues)
        let (bridge_tx, bridge_rx) = channel::channel(1000);

        Self {
            ssh_handler: SshHandler::new(
                settings.clone(),
                Arc::clone(&auth_cache),
                host_key,
            ),
            bridge_channels: HashMap::new(),
            bridge_rx,
            buffer_pool,
            session_guard: None,
            auth_cache,
            initial_window_size: settings.initial_window_size,
            authenticated: false,
            settings,
        }
    }

    pub async fn run(&mut self, mut stream: UnixStream) -> Result<()> {
        info!("SSH connection started");

        let mut read_buffer = vec![0u8; 65536];

        loop {
            let (result, buf) = stream.read(read_buffer).await;
            read_buffer = buf;

            match result {
                Ok(0) => {
                    info!(
                        user = ?self.ssh_handler.username(),
                        bridges = self.bridge_channels.len(),
                        "SSH connection closed"
                    );
                    break;
                }
                Ok(n) => {
                    let data = &read_buffer[..n];
                    debug!("← {} bytes from SSH client", n);

                    match self.ssh_handler.process_data(data).await {
                        Ok(Some(response)) => {
                            debug!("→ {} bytes SSH response", response.len());
                            let response_vec = response.to_vec();
                            let (write_result, _) = stream.write_all(response_vec).await;
                            write_result?;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            error!("SSH handler error: {:?}", e);
                            break;
                        }
                    }

                    if !self.authenticated && self.ssh_handler.is_authenticated() {
                        self.create_session_guard();
                    }

                    if self.authenticated {
                        // Process new channel opens (spawns async tasks)
                        self.process_new_channels().await?;

                        // Forward channel data to TCP targets via channels
                        let channel_handler = self.ssh_handler.channel_handler_mut();
                        let pending_data = channel_handler.take_pending_data();
                        for pending in pending_data {
                            if let Some(tx) = self.bridge_channels.get(&pending.channel_id) {
                                if tx.send(SshToBridgeMessage::Data(pending.data)).await.is_err() {
                                    warn!(channel = pending.channel_id, "Bridge channel closed");
                                    self.bridge_channels.remove(&pending.channel_id);
                                }
                            }
                        }
                        
                        // Process messages from bridge tasks (non-blocking)
                        while let Ok(msg) = self.bridge_rx.try_recv() {
                            match msg {
                                BridgeMessage::Data { channel_id, msg } => {
                                    if msg.len() > 0 {
                                        let msg_type = msg[0];
                                        let payload = &msg[1..];
                                        let encoded = self.ssh_handler.transport_mut().encode_message(msg_type, payload)?;
                                        let encoded_vec = encoded.to_vec();
                                        let (write_result, _) = stream.write_all(encoded_vec).await;
                                        write_result?;
                                    }
                                }
                                BridgeMessage::Eof { channel_id } => {
                                    debug!(channel = channel_id, "Bridge sent EOF");
                                    // Send EOF message to client
                                    let eof_msg = bytes::BytesMut::from(&[SSH_MSG_CHANNEL_EOF][..]);
                                    if let Ok(encoded) = self.ssh_handler.transport_mut().encode_message(SSH_MSG_CHANNEL_EOF, &[]) {
                                        let (write_result, _) = stream.write_all(encoded.to_vec()).await;
                                        let _ = write_result;
                                    }
                                }
                                BridgeMessage::Close { channel_id } => {
                                    info!(channel = channel_id, "Bridge closed");
                                    self.bridge_channels.remove(&channel_id);
                                }
                                BridgeMessage::Error { channel_id, error } => {
                                    error!(channel = channel_id, error = %error, "Bridge error");
                                    self.bridge_channels.remove(&channel_id);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Read error: {:?}", e);
                    break;
                }
            }
        }

        info!("Connection manager shutting down");
        Ok(())
    }

    fn create_session_guard(&mut self) {
        if let Some(username) = self.ssh_handler.username() {
            self.session_guard = Some(SessionGuard::new(
                username.to_string(),
                Arc::clone(&self.auth_cache),
            ));
            self.authenticated = true;
            info!("User authenticated: {}", username);
        }
    }

    /// PRODUCTION: Spawn async tasks for each bridge (connection already verified in channel handler)
    async fn process_new_channels(&mut self) -> Result<()> {
        let channel_handler = self.ssh_handler.channel_handler_mut();
        let pending = channel_handler.take_pending_forwards();

        for forward in pending {
            info!(
                channel = forward.local_channel_id,
                target = %format!("{}:{}", forward.target_host, forward.target_port),
                "Spawning bridge task"
            );

            // Create channels for bidirectional communication
            let (ssh_to_bridge_tx, ssh_to_bridge_rx) = channel::channel(100);
            let bridge_tx = self.bridge_rx.sender().clone();

            let channel_id = forward.local_channel_id;
            let remote_channel_id = forward.remote_channel_id;
            let target_host = forward.target_host.clone();
            let target_port = forward.target_port;
            let buffer_pool = Arc::clone(&self.buffer_pool);
            let initial_window = self.initial_window_size;

            // Store sender for this bridge
            self.bridge_channels.insert(channel_id, ssh_to_bridge_tx);

            // Spawn dedicated task for this bridge
            monoio::spawn(async move {
                if let Err(e) = Self::bridge_task(
                    channel_id,
                    remote_channel_id,
                    target_host,
                    target_port,
                    buffer_pool,
                    initial_window,
                    ssh_to_bridge_rx,
                    bridge_tx,
                ).await {
                    error!(channel = channel_id, error = ?e, "Bridge task failed");
                    let _ = bridge_tx.send(BridgeMessage::Error {
                        channel_id,
                        error: e.to_string(),
                    }).await;
                }
            });
        }

        Ok(())
    }

    /// Bridge task - handles bidirectional forwarding for a single channel
    async fn bridge_task(
        channel_id: u32,
        remote_channel_id: u32,
        target_host: String,
        target_port: u32,
        buffer_pool: Arc<BufferPool>,
        initial_window: u32,
        mut ssh_to_bridge_rx: channel::Receiver<SshToBridgeMessage>,
        bridge_tx: channel::Sender<BridgeMessage>,
    ) -> Result<()> {
        // Create and connect bridge
        let mut bridge = BidirectionalBridge::new(
            channel_id,
            remote_channel_id,
            target_host.clone(),
            target_port,
            buffer_pool,
            initial_window,
        );

        // Connect to target (should already be verified, but reconnect for the task)
        bridge.connect_target().await?;

        info!(channel = channel_id, "Bridge task started");

        // Spawn task for reading from target TCP
        let bridge_tx_clone = bridge_tx.clone();
        let mut bridge_for_read = bridge;
        let read_handle = monoio::spawn(async move {
            loop {
                match bridge_for_read.read_from_target().await {
                    Ok(Some(msg)) => {
                        if bridge_tx_clone.send(BridgeMessage::Data {
                            channel_id,
                            msg,
                        }).await.is_err() {
                            break; // Main loop closed
                        }
                    }
                    Ok(None) => {
                        // EOF from target
                        let _ = bridge_tx_clone.send(BridgeMessage::Eof { channel_id }).await;
                        break;
                    }
                    Err(e) => {
                        error!(channel = channel_id, error = ?e, "Bridge read error");
                        let _ = bridge_tx_clone.send(BridgeMessage::Error {
                            channel_id,
                            error: e.to_string(),
                        }).await;
                        break;
                    }
                }
            }
        });

        // Handle SSH -> Target forwarding in main task

        read_handle.await;

        let _ = bridge_tx.send(BridgeMessage::Close { channel_id }).await;
        Ok(())
    }

}

impl Drop for ConnectionManager {
    fn drop(&mut self) {
        info!(
            user = ?self.ssh_handler.username(),
            bridges = self.bridge_channels.len(),
            "Connection dropped"
        );
    }
}

fn extract_channel_id(payload: &[u8]) -> Option<u32> {
    if payload.len() >= 4 {
        Some(u32::from_be_bytes([
            payload[0], payload[1], payload[2], payload[3]
        ]))
    } else {
        None
    }
}

fn extract_channel_data(payload: &[u8]) -> Option<(u32, Vec<u8>)> {
    if payload.len() < 8 {
        return None;
    }

    let channel_id = u32::from_be_bytes([
        payload[0], payload[1], payload[2], payload[3]
    ]);
    let data_len = u32::from_be_bytes([
        payload[4], payload[5], payload[6], payload[7]
    ]) as usize;

    if payload.len() < 8 + data_len {
        return None;
    }

    let data = payload[8..8 + data_len].to_vec();
    Some((channel_id, data))
}