use anyhow::Result;
use monoio::net::UnixListener;
use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
use std::sync::Arc;
use std::path::Path;
use tracing::{info, error, debug};

use crate::auth::AuthCache;
use super::api::{AdminRequest, AdminResponse};
use super::handlers::AdminHandler;

/// Admin socket listener
pub struct AdminSocketListener {
    socket_path: String,
    auth_cache: Arc<AuthCache>,
}

impl AdminSocketListener {
    pub fn new(socket_path: String, auth_cache: Arc<AuthCache>) -> Self {
        Self {
            socket_path,
            auth_cache,
        }
    }

    /// Start listening on admin socket
    pub async fn listen(self) -> Result<()> {
        let path = Path::new(&self.socket_path);

        // Remove old socket if exists
        let _ = std::fs::remove_file(path);

        // Create listener
        let listener = UnixListener::bind(path)?;

        info!("Admin socket listening on: {}", self.socket_path);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let auth_cache = Arc::clone(&self.auth_cache);

                    // Spawn handler task
                    monoio::spawn(async move {
                        if let Err(e) = handle_admin_connection(stream, auth_cache).await {
                            error!("Admin connection error: {:?}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Admin accept error: {:?}", e);
                }
            }
        }
    }
}

/// Handle a single admin connection
async fn handle_admin_connection(
    mut stream: monoio::net::UnixStream,
    auth_cache: Arc<AuthCache>,
) -> Result<()> {
    debug!("New admin connection");

    let mut buffer = vec![0u8; 8192];

    // Read request
    let (result, buf) = stream.read(buffer).await;
    buffer = buf;

    let n = result?;

    if n == 0 {
        return Ok(());
    }

    let request_data = &buffer[..n];

    // Parse request
    let request: AdminRequest = match serde_json::from_slice(request_data) {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to parse admin request: {:?}", e);
            let response = AdminResponse::error("Invalid JSON");
            let response_data = serde_json::to_vec(&response)?;
            let (_, _) = stream.write_all(response_data).await;
            return Ok(());
        }
    };

    debug!("Admin request: {:?}", request);

    // Handle request
    let handler = AdminHandler::new(auth_cache);
    let response = handler.handle_request(request).await;

    // Send response
    let response_data = serde_json::to_vec(&response)?;
    let (result, _) = stream.write_all(response_data).await;
    result?;

    debug!("Admin response sent");

    Ok(())
}