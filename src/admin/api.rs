use serde::{Deserialize, Serialize};

/// Admin request types
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "command")]
pub enum AdminRequest {
    /// List all active sessions
    #[serde(rename = "sessions")]
    ListSessions,

    /// Force disconnect a user (all their sessions)
    #[serde(rename = "disconnect")]
    Disconnect { user: String },

    /// Reload users from database
    #[serde(rename = "reload")]
    Reload,

    /// Get server statistics
    #[serde(rename = "stats")]
    Stats,

    /// Get user info
    #[serde(rename = "user_info")]
    UserInfo { user: String },

    /// Cleanup expired users from cache
    #[serde(rename = "cleanup")]
    CleanupExpired,
}

/// Admin response
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status")]
pub enum AdminResponse {
    /// Success with optional data
    #[serde(rename = "success")]
    Success {
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,

        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },

    /// Error response
    #[serde(rename = "error")]
    Error {
        error: String,
    },
}

impl AdminResponse {
    pub fn success() -> Self {
        Self::Success {
            data: None,
            message: None,
        }
    }

    pub fn success_with_message(message: impl Into<String>) -> Self {
        Self::Success {
            data: None,
            message: Some(message.into()),
        }
    }

    pub fn success_with_data(data: impl Serialize) -> Self {
        Self::Success {
            data: serde_json::to_value(data).ok(),
            message: None,
        }
    }

    pub fn error(error: impl Into<String>) -> Self {
        Self::Error {
            error: error.into(),
        }
    }
}

/// Session information
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub username: String,
    pub active_sessions: u32,
    pub max_logins: u32,
}

/// Server statistics
#[derive(Debug, Clone, Serialize)]
pub struct ServerStats {
    pub total_users: usize,
    pub total_sessions: usize,
    pub uptime_seconds: u64,
}

/// User information
#[derive(Debug, Clone, Serialize)]
pub struct UserInfo {
    pub username: String,
    pub active_sessions: u32,
    pub max_logins: u32,
    pub expiry_date: String,
    pub expired: bool,
}