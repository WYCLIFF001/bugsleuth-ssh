use std::sync::Arc;
use tracing::{info, warn};

use crate::auth::AuthCache;
use super::api::{AdminRequest, AdminResponse, SessionInfo, ServerStats, UserInfo};

/// Admin request handler
pub struct AdminHandler {
    auth_cache: Arc<AuthCache>,
}

impl AdminHandler {
    pub fn new(auth_cache: Arc<AuthCache>) -> Self {
        Self { auth_cache }
    }

    /// Handle admin request
    pub async fn handle_request(&self, request: AdminRequest) -> AdminResponse {
        match request {
            AdminRequest::ListSessions => self.handle_list_sessions(),
            AdminRequest::Disconnect { user } => self.handle_disconnect(user),
            AdminRequest::Reload => self.handle_reload(),
            AdminRequest::Stats => self.handle_stats(),
            AdminRequest::UserInfo { user } => self.handle_user_info(user),
            AdminRequest::CleanupExpired => self.handle_cleanup_expired(),
        }
    }

    /// List all active sessions
    fn handle_list_sessions(&self) -> AdminResponse {
        let sessions = self.auth_cache.sessions();
        let all_sessions = sessions.all_sessions();

        let session_infos: Vec<SessionInfo> = all_sessions
            .into_iter()
            .map(|(username, active_count)| {
                let max_logins = self.auth_cache.get_user_max_logins(&username)
                    .unwrap_or(0);

                SessionInfo {
                    username,
                    active_sessions: active_count,
                    max_logins,
                }
            })
            .collect();

        info!("Listed {} active sessions", session_infos.len());
        AdminResponse::success_with_data(session_infos)
    }

    /// Force disconnect a user
    fn handle_disconnect(&self, username: String) -> AdminResponse {
        let sessions = self.auth_cache.sessions();
        let disconnected = sessions.force_disconnect(&username);

        if disconnected > 0 {
            info!(
                "Force disconnected user: {}, sessions: {}",
                username, disconnected
            );
            AdminResponse::success_with_message(format!(
                "Disconnected {} session(s) for user: {}",
                disconnected, username
            ))
        } else {
            warn!("Attempted to disconnect non-existent user: {}", username);
            AdminResponse::error(format!("User '{}' has no active sessions", username))
        }
    }

    /// Reload users from database
    fn handle_reload(&self) -> AdminResponse {
        match self.auth_cache.reload() {
            Ok(_) => {
                let count = self.auth_cache.user_count();
                info!("Reloaded auth cache: {} users", count);
                AdminResponse::success_with_message(format!(
                    "Reloaded {} users from database",
                    count
                ))
            }
            Err(e) => {
                warn!("Failed to reload auth cache: {:?}", e);
                AdminResponse::error(format!("Failed to reload: {}", e))
            }
        }
    }

    /// Get server statistics
    fn handle_stats(&self) -> AdminResponse {
        let sessions = self.auth_cache.sessions();
        let all_sessions = sessions.all_sessions();

        let total_sessions: usize = all_sessions
            .iter()
            .map(|(_, count)| *count as usize)
            .sum();

        // Calculate uptime from process start time
        // The runtime stores the start time in an environment variable at startup
        // to ensure accurate uptime tracking across the lifetime of the process
        let uptime_seconds = match std::env::var("BUGSLEUTH_START_TIME") {
            Ok(start_time_str) => {
                if let Ok(start_time) = start_time_str.parse::<u64>() {
                    // Calculate uptime from start time (in seconds since epoch)
                    let current_time = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    current_time.saturating_sub(start_time)
                } else {
                    0
                }
            }
            Err(_) => {
                // Fallback: No start time tracked, return 0
                0
            }
        };

        let stats = ServerStats {
            total_users: self.auth_cache.user_count(),
            total_sessions,
            uptime_seconds,
        };

        AdminResponse::success_with_data(stats)
    }

    /// Get user information
    fn handle_user_info(&self, username: String) -> AdminResponse {
        let active_sessions = self.auth_cache.active_logins(&username);

        let max_logins = match self.auth_cache.get_user_max_logins(&username) {
            Some(max) => max,
            None => {
                return AdminResponse::error(format!("User '{}' not found", username));
            }
        };

        let expiry_date = self.auth_cache.get_user_expiry(&username)
            .unwrap_or_else(|| "unknown".to_string());

        let expired = self.auth_cache.is_user_expired(&username).unwrap_or(true);

        let info = UserInfo {
            username,
            active_sessions,
            max_logins,
            expiry_date,
            expired,
        };

        AdminResponse::success_with_data(info)
    }

    /// Cleanup expired users from cache
    fn handle_cleanup_expired(&self) -> AdminResponse {
        // Reload from database (this automatically removes expired users)
        match self.auth_cache.reload() {
            Ok(_) => {
                let count = self.auth_cache.user_count();
                info!("Cleaned up expired users, {} active users remaining", count);
                AdminResponse::success_with_message(format!(
                    "{} active users after cleanup",
                    count
                ))
            }
            Err(e) => {
                warn!("Failed to cleanup expired users: {:?}", e);
                AdminResponse::error(format!("Cleanup failed: {}", e))
            }
        }
    }
}