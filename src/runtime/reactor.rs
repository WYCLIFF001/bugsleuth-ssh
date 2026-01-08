use std::sync::Arc;
use anyhow::Result;
use tracing::info;

use crate::config::Settings;
use crate::auth::AuthCache;
use crate::ssh::keys::HostKey;  // ADD THIS
use crate::admin::AdminSocketListener;
use super::workers::WorkerPool;

pub struct Runtime {
    settings: Settings,
    auth_cache: Arc<AuthCache>,
    host_key: Arc<HostKey>,  // ADD THIS
    workers: WorkerPool,
}

impl Runtime {
    pub fn new(
        settings: Settings,
        auth_cache: Arc<AuthCache>,
        host_key: Arc<HostKey>,  // ADD THIS PARAMETER
    ) -> Result<Self> {
        std::fs::create_dir_all(&settings.socket_dir)?;

        let worker_count = settings.worker_count();
        let workers = WorkerPool::new(
            worker_count,
            settings.clone(),
            Arc::clone(&auth_cache),
            Arc::clone(&host_key),  // PASS TO WORKERS
        )?;

        Ok(Self {
            settings,
            auth_cache,
            host_key,  // ADD THIS
            workers,
        })
    }

    pub async fn run(self) -> Result<()> {
        info!("Starting {} worker threads", self.workers.count());

        let admin_listener = AdminSocketListener::new(
            self.settings.admin_socket_path().to_string_lossy().to_string(),
            Arc::clone(&self.auth_cache),
        );

        monoio::spawn(async move {
            if let Err(e) = admin_listener.listen().await {
                tracing::error!("Admin listener error: {:?}", e);
            }
        });

        self.workers.start().await?;

        Ok(())
    }

    pub fn admin_socket_path(&self) -> String {
        self.settings.admin_socket_path().to_string_lossy().to_string()
    }

    pub fn worker_count(&self) -> usize {
        self.workers.count()
    }
}