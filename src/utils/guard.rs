use std::sync::Arc;
use crate::auth::AuthCache;

/// RAII guard for session cleanup
/// Guarantees decrement on drop
pub struct SessionGuard {
    username: String,
    auth_cache: Arc<AuthCache>,
    active: bool,
}

impl SessionGuard {
    pub fn new(username: String, auth_cache: Arc<AuthCache>) -> Self {
        Self {
            username,
            auth_cache,
            active: true,
        }
    }

    /// Manually release (for testing)
    pub fn release(mut self) {
        self.active = false;
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if self.active {
            self.auth_cache.record_logout(&self.username);
            tracing::debug!(username = %self.username, "Session guard dropped");
        }
    }
}

/// RAII guard for channel cleanup
pub struct ChannelGuard {
    channel_id: u32,
}

impl ChannelGuard {
    pub fn new(channel_id: u32) -> Self {
        Self { channel_id }
    }
}

impl Drop for ChannelGuard {
    fn drop(&mut self) {
        tracing::debug!(channel_id = self.channel_id, "Channel guard dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthCache;
    use std::path::Path;

    #[test]
    fn test_session_guard() -> anyhow::Result<()> {
        let cache = Arc::new(AuthCache::load(Path::new(":memory:"))?);

        {
            let _guard = SessionGuard::new("test".to_string(), cache.clone());
            // Guard should auto-cleanup on drop
        }

        Ok(())
    }
}