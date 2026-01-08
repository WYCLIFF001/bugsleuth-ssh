use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use anyhow::Result;
use parking_lot::RwLock;

use super::db::{self};
use super::sessions::SessionTracker;

/// In-memory authentication data (with max_logins for abuse control)
#[derive(Debug, Clone)]
pub struct UserAuth {
    pub password: String,
    pub expiry_date: String,
    pub max_logins: u32,
}

/// Thread-safe authentication cache
pub struct AuthCache {
    users: RwLock<HashMap<String, UserAuth>>,
    sessions: Arc<SessionTracker>,
    db_path: String,
}

impl AuthCache {
    /// Load users from database and create cache
    pub fn load(db_path: &Path) -> Result<Self> {
        // Initialize DB if needed
        db::init_db(db_path)?;

        // Try to migrate existing tables
        let _ = db::migrate_add_max_logins(db_path);

        // Load all active (non-expired) users
        let db_users = db::load_enabled_users(db_path)?;

        let mut users = HashMap::new();
        for user in db_users {
            users.insert(
                user.username.clone(),
                UserAuth {
                    password: user.password,
                    expiry_date: user.expiry_date,
                    max_logins: user.max_logins,
                },
            );
        }

        Ok(Self {
            users: RwLock::new(users),
            sessions: Arc::new(SessionTracker::new()),
            db_path: db_path.to_string_lossy().to_string(),
        })
    }

    /// Authenticate a user (checks password, expiry, and login limits)
    pub fn authenticate(&self, username: &str, password: &str) -> Result<bool, AuthError> {
        let users = self.users.read();

        // Look up user
        let user_auth = users.get(username)
            .ok_or(AuthError::UserNotFound)?;

        // Verify password
        if user_auth.password != password {
            return Err(AuthError::InvalidPassword);
        }

        // Check if user is expired - Fixed: use internal error type
        if self.is_user_expired_internal(user_auth) {
            return Err(AuthError::UserExpired);
        }

        // Check login limit
        if !self.sessions.can_login(username, user_auth.max_logins) {
            return Err(AuthError::LoginLimitExceeded);
        }

        Ok(true)
    }

    /// Check if user is expired (internal helper) - Fixed: return bool instead of Result
    fn is_user_expired_internal(&self, user_auth: &UserAuth) -> bool {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        user_auth.expiry_date <= now
    }

    /// Check if user is expired (public API)
    pub fn is_user_expired(&self, username: &str) -> Result<bool> {
        let users = self.users.read();

        if let Some(user_auth) = users.get(username) {
            Ok(self.is_user_expired_internal(user_auth))
        } else {
            Ok(true) // User not found = expired
        }
    }

    /// Record successful login
    pub fn record_login(&self, username: &str) {
        self.sessions.increment_login(username);
    }

    /// Record logout
    pub fn record_logout(&self, username: &str) {
        self.sessions.decrement_login(username);
    }

    /// Get current active logins for a user
    pub fn active_logins(&self, username: &str) -> u32 {
        self.sessions.active_logins(username)
    }

    /// Get number of cached users
    pub fn user_count(&self) -> usize {
        self.users.read().len()
    }

    /// Get session tracker reference
    pub fn sessions(&self) -> Arc<SessionTracker> {
        Arc::clone(&self.sessions)
    }

    /// Reload users from database (for hot reload)
    pub fn reload(&self) -> Result<()> {
        let db_path = Path::new(&self.db_path);
        let db_users = db::load_enabled_users(db_path)?;

        let mut new_users = HashMap::new();
        for user in db_users {
            new_users.insert(
                user.username.clone(),
                UserAuth {
                    password: user.password,
                    expiry_date: user.expiry_date,
                    max_logins: user.max_logins,
                },
            );
        }

        // Atomic swap
        let mut users = self.users.write();
        *users = new_users;

        tracing::info!("Auth cache reloaded: {} users", users.len());
        Ok(())
    }

    /// Get user expiry date
    pub fn get_user_expiry(&self, username: &str) -> Option<String> {
        let users = self.users.read();
        users.get(username).map(|u| u.expiry_date.clone())
    }

    /// Get user max logins
    pub fn get_user_max_logins(&self, username: &str) -> Option<u32> {
        let users = self.users.read();
        users.get(username).map(|u| u.max_logins)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("User not found")]
    UserNotFound,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("User account expired")]
    UserExpired,

    #[error("Login limit exceeded")]
    LoginLimitExceeded,
}