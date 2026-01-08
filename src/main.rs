use anyhow::Result;
use tracing::info;
use std::sync::Arc;

mod config;
mod runtime;
mod ssh;
mod auth;
mod forwarder;
mod admin;
mod utils;
mod pool;

use config::Settings;
use runtime::Runtime;
use auth::AuthCache;
use crate::ssh::keys::HostKey;
// ADD THIS

#[monoio::main(driver = "uring")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("Starting SSH Direct-TCPIP Forwarding Engine v0.1.0");
    info!("High-performance: io_uring + custom auth + zero-copy");

    let settings = Settings::default();
    info!("Configuration loaded");
    info!("  Workers: {}", settings.worker_count());
    info!("  Initial window: {} bytes", settings.initial_window_size);

    // LOAD OR GENERATE HOST KEY (CRITICAL!)
    let host_key_path = settings.host_key_path.clone();
    let host_key = HostKey::load_or_generate(&host_key_path)?;
    let host_key = Arc::new(host_key);

    info!("🔑 Host key loaded");
    info!("   Path: {}", host_key_path.display());
    info!("   Fingerprint: {}", host_key.fingerprint());

    // Load auth cache
    let auth_cache = AuthCache::load(&settings.db_path)?;
    info!("Auth cache loaded: {} users", auth_cache.user_count());

    // Create/ensure test user exists with auto-generated password
    let (test_username, test_password) = crate::auth::db::ensure_test_user(&settings.db_path)?;
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("🧪 TEST USER CREATED");
    info!("   Username: {}", test_username);
    info!("   Password: {}", test_password);
    info!("   Max Logins: 5");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Reload cache to include test user
    let auth_cache = AuthCache::load(&settings.db_path)?;
    let auth_cache = Arc::new(auth_cache);

    // Initialize runtime WITH HOST KEY
    let runtime = Runtime::new(settings, auth_cache, host_key)?;

    info!("Runtime initialized");
    info!("Listening on UDS sockets:");
    info!("  - Admin: {}", runtime.admin_socket_path());
    info!("  - Traffic sockets: {} (one per core)", runtime.worker_count());

    runtime.run().await?;

    info!("Shutdown complete");
    Ok(())
}
