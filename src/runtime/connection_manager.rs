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
        host_key: Arc<HostKey>,  // ADD THIS PARAMETER
    ) -> Self {
        let buffer_pool = BufferPool::new(
            settings.standard_buffer_size,
            settings.high_throughput_buffer_size,
        );

        Self {
            ssh_handler: SshHandler::new(
                settings.clone(),
                Arc::clone(&auth_cache),
                host_key,  // PASS TO SSH HANDLER
            ),
            bridges: HashMap::new(),
            buffer_pool,
            session_guard: None,
            auth_cache,
            initial_window_size: settings.initial_window_size,
            authenticated: false,
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
                        bridges = self.bridges.len(),
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
                        self.process_new_channels().await?;

                        if n > 0 {
                            match data[0] {
                                SSH_MSG_CHANNEL_DATA => {
                                    if let Some((cid, payload)) = extract_channel_data(&data[1..]) {
                                        self.forward_to_target(cid, &payload).await?;
                                    }
                                }
                                SSH_MSG_CHANNEL_EOF => {
                                    if let Some(cid) = extract_channel_id(&data[1..]) {
                                        self.handle_ssh_eof(cid).await?;
                                    }
                                }
                                SSH_MSG_CHANNEL_CLOSE => {
                                    if let Some(cid) = extract_channel_id(&data[1..]) {
                                        self.close_bridge(cid);
                                    }
                                }
                                _ => {}
                            }
                        }

                        let messages = self.read_from_all_bridges().await?;
                        for msg in messages {
                            let msg_vec = msg.to_vec();
                            let (write_result, _) = stream.write_all(msg_vec).await;
                            write_result?;
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

    async fn process_new_channels(&mut self) -> Result<()> {
        let channel_handler = self.ssh_handler.channel_handler_mut();
        let pending = channel_handler.take_pending_forwards();

        for forward in pending {
            info!(
                channel = forward.local_channel_id,
                target = %format!("{}:{}", forward.target_host, forward.target_port),
                "Creating TCP bridge"
            );

            let mut bridge = BidirectionalBridge::new(
                forward.local_channel_id,
                forward.remote_channel_id,
                forward.target_host.clone(),
                forward.target_port,
                Arc::clone(&self.buffer_pool),
                self.initial_window_size,
            );

            match bridge.connect_target().await {
                Ok(_) => {
                    self.bridges.insert(forward.local_channel_id, bridge);
                }
                Err(e) => {
                    error!(
                        channel = forward.local_channel_id,
                        error = ?e,
                        "Failed to connect to target"
                    );
                }
            }
        }

        Ok(())
    }

    async fn forward_to_target(&mut self, channel_id: u32, data: &[u8]) -> Result<()> {
        if let Some(bridge) = self.bridges.get_mut(&channel_id) {
            bridge.forward_ssh_to_target(data).await?;
        } else {
            warn!(channel = channel_id, "Data for unknown channel");
        }
        Ok(())
    }

    async fn handle_ssh_eof(&mut self, channel_id: u32) -> Result<()> {
        if let Some(bridge) = self.bridges.get_mut(&channel_id) {
            bridge.handle_ssh_close().await?;
        }
        Ok(())
    }

    fn close_bridge(&mut self, channel_id: u32) {
        if let Some(_bridge) = self.bridges.remove(&channel_id) {
            info!(channel = channel_id, "Bridge closed");
        }
    }

    async fn read_from_all_bridges(&mut self) -> Result<Vec<bytes::BytesMut>> {
        let mut messages = Vec::new();
        let channel_ids: Vec<u32> = self.bridges.keys().copied().collect();

        for channel_id in channel_ids {
            if let Some(bridge) = self.bridges.get_mut(&channel_id) {
                match bridge.read_from_target().await {
                    Ok(Some(ssh_msg)) => {
                        messages.push(ssh_msg);
                    }
                    Ok(None) => {
                        let eof_msg = bridge.build_channel_eof();
                        messages.push(eof_msg);
                        bridge.mark_ssh_eof_sent();

                        if bridge.is_fully_closed() {
                            let close_msg = bridge.build_channel_close();
                            messages.push(close_msg);
                        }
                    }
                    Err(e) => {
                        error!(channel = channel_id, error = ?e, "Bridge read error");
                        if let Some(bridge) = self.bridges.get(&channel_id) {
                            let close_msg = bridge.build_channel_close();
                            messages.push(close_msg);
                        }
                    }
                }
            }
        }

        self.bridges.retain(|_, bridge| !bridge.is_fully_closed());

        Ok(messages)
    }
}

impl Drop for ConnectionManager {
    fn drop(&mut self) {
        info!(
            user = ?self.ssh_handler.username(),
            bridges = self.bridges.len(),
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