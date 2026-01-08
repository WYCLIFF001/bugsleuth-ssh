use std::sync::Arc;
use anyhow::Result;
use tracing::{info, error};

use crate::config::Settings;
use crate::auth::AuthCache;
use crate::ssh::keys::HostKey;  // ADD THIS
use crate::runtime::connection_manager::ConnectionManager;

pub struct WorkerPool {
    count: usize,
    settings: Settings,
    auth_cache: Arc<AuthCache>,
    host_key: Arc<HostKey>,  // ADD THIS
}

impl WorkerPool {
    pub fn new(
        count: usize,
        settings: Settings,
        auth_cache: Arc<AuthCache>,
        host_key: Arc<HostKey>,  // ADD THIS PARAMETER
    ) -> Result<Self> {
        Ok(Self {
            count,
            settings,
            auth_cache,
            host_key,  // ADD THIS
        })
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub async fn start(self) -> Result<()> {
        let mut handles = Vec::new();

        for worker_id in 0..self.count {
            let settings = self.settings.clone();
            let auth_cache = Arc::clone(&self.auth_cache);
            let host_key = Arc::clone(&self.host_key);  // ADD THIS

            let handle = std::thread::spawn(move || {
                let mut rt = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
                    .enable_timer()
                    .build()
                    .expect("Failed to build monoio runtime");

                rt.block_on(async move {
                    if let Err(e) = worker_main(
                        worker_id,
                        settings,
                        auth_cache,
                        host_key,  // PASS TO WORKER
                    ).await {
                        error!(worker_id = worker_id, error = ?e, "Worker failed");
                    }
                });
            });

            handles.push(handle);
        }

        info!("All {} workers started", self.count);

        for handle in handles {
            handle.join().expect("Worker thread panicked");
        }

        Ok(())
    }
}

async fn worker_main(
    worker_id: usize,
    settings: Settings,
    auth_cache: Arc<AuthCache>,
    host_key: Arc<HostKey>,  // ADD THIS PARAMETER
) -> Result<()> {
    info!(worker_id = worker_id, "Worker starting");

    let socket_path = settings.traffic_socket_path(worker_id);

    let _ = std::fs::remove_file(&socket_path);

    let listener = monoio::net::UnixListener::bind(&socket_path)?;

    info!(
        worker_id = worker_id,
        socket = ?socket_path,
        "Worker listening on UDS"
    );

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let auth_cache = Arc::clone(&auth_cache);
                let host_key = Arc::clone(&host_key);  // ADD THIS
                let settings = settings.clone();

                monoio::spawn(async move {
                    info!("New SSH connection accepted");
                    let mut conn_manager = ConnectionManager::new(
                        settings,
                        auth_cache,
                        host_key,  // PASS TO CONNECTION MANAGER
                    );

                    if let Err(e) = conn_manager.run(stream).await {
                        error!(error = ?e, "Connection manager failed");
                    }

                    info!("SSH connection closed");
                });
            }
            Err(e) => {
                error!(worker_id = worker_id, error = ?e, "Accept failed");
            }
        }
    }
}