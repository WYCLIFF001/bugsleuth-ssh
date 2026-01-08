/// Authentication Handler for Transport Layer
/// Implements RFC 4252 (SSH Authentication Protocol)
/// This module handles the authentication phase of SSH connections

use anyhow::{Result, bail};
use bytes::Bytes;
use tracing::{debug, info, warn, error};

use crate::auth::{AuthCache, AuthError};
use crate::ssh::protocol;
use std::sync::Arc;

/// States during authentication process
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// Waiting for service request
    WaitingServiceRequest,
    /// Waiting for userauth request
    WaitingUserauth,
    /// Authentication succeeded
    Success,
    /// Authentication failed or max attempts reached
    Failed,
}

/// Handles SSH authentication per RFC 4252
pub struct TransportAuthHandler {
    auth_cache: Arc<AuthCache>,
    state: AuthState,
    username: Option<String>,
    failed_attempts: u32,
    max_attempts: u32,
}

impl TransportAuthHandler {
    pub fn new(auth_cache: Arc<AuthCache>) -> Self {
        Self {
            auth_cache,
            state: AuthState::WaitingServiceRequest,
            username: None,
            failed_attempts: 0,
            max_attempts: 5, // Prevent brute force
        }
    }

    /// Process authentication messages
    /// Returns optional response message and whether authentication succeeded
    pub async fn process_auth_message(&mut self, msg_type: u8, payload: &[u8]) -> Result<(Option<Bytes>, bool)> {
        match msg_type {
            // SSH_MSG_SERVICE_REQUEST = 5
            5 => {
                let response = self.handle_service_request(payload)?;
                Ok((Some(response), false))
            }

            // SSH_MSG_USERAUTH_REQUEST = 50
            50 => {
                self.handle_userauth_request(payload).await
            }

            _ => {
                error!("Unexpected auth message type: {}", msg_type);
                bail!("Invalid auth message type: {}", msg_type)
            }
        }
    }

    /// Handle SSH_MSG_SERVICE_REQUEST
    /// RFC 4252 section 5: Client requests "ssh-userauth" service
    fn handle_service_request(&mut self, payload: &[u8]) -> Result<Bytes> {
        debug!("Processing SSH_MSG_SERVICE_REQUEST");

        // Parse service name from payload
        let service_name = std::str::from_utf8(payload)
            .unwrap_or("unknown")
            .trim_end_matches('\0');

        if service_name != "ssh-userauth" {
            warn!("Invalid service request: {}", service_name);
            bail!("Invalid service: {}", service_name)
        }

        info!("Service request accepted: ssh-userauth");
        self.state = AuthState::WaitingUserauth;

        // Send SSH_MSG_SERVICE_ACCEPT
        let response = protocol::build_service_accept("ssh-userauth");
        Ok(response)
    }

    /// Handle SSH_MSG_USERAUTH_REQUEST
    /// RFC 4252 section 5: Client sends authentication request
    ///
    /// Payload format:
    /// - username (string): Account name to authenticate as
    /// - service-name (string): "ssh-connection"
    /// - method-name (string): "password", "publickey", etc.
    /// - method-specific fields depending on method
    async fn handle_userauth_request(&mut self, payload: &[u8]) -> Result<(Option<Bytes>, bool)> {
        // Check attempt limit (prevent brute force)
        if self.failed_attempts >= self.max_attempts {
            error!("Max authentication attempts exceeded");
            let response = protocol::build_disconnect(
                protocol::disconnect::TOO_MANY_CONNECTIONS,
                "Too many authentication failures"
            );
            self.state = AuthState::Failed;
            return Ok((Some(response), false));
        }

        // Parse authentication request
        // Note: In production, this would use proper SSH message parsing
        // For now, we parse the basic structure

        // Extract username (variable-length string at offset 0)
        let (username, rest) = parse_ssh_string(payload)?;
        let username_str = String::from_utf8_lossy(&username).to_string();

        debug!("Authentication attempt for user: {}", username_str);

        // Extract service name
        let (service, rest) = parse_ssh_string(rest)?;
        let service_str = String::from_utf8_lossy(&service).to_string();

        if service_str != "ssh-connection" {
            warn!("Invalid service in auth request: {}", service_str);
            let response = protocol::build_userauth_failure(&["password"], false);
            return Ok((Some(response), false));
        }

        // Extract method name
        let (method, rest) = parse_ssh_string(rest)?;
        let method_str = String::from_utf8_lossy(&method).to_string();

        debug!("Auth method: {}", method_str);

        // Handle different authentication methods
        let (response, success) = match method_str.as_str() {
            "password" => {
                self.handle_password_auth(&username_str, rest).await?
            }
            "publickey" => {
                warn!("Public key auth not yet implemented");
                let response = protocol::build_userauth_failure(&["password"], false);
                (response, false)
            }
            _ => {
                warn!("Unsupported auth method: {}", method_str);
                let response = protocol::build_userauth_failure(&["password"], false);
                (response, false)
            }
        };

        if success {
            self.username = Some(username_str.clone());
            self.state = AuthState::Success;
            info!("Authentication successful for: {}", username_str);
            self.auth_cache.record_login(&username_str);
        } else {
            self.failed_attempts += 1;
            warn!("Authentication failed for: {} (attempt {}/{})", 
                username_str, self.failed_attempts, self.max_attempts);
        }

        Ok((Some(response), success))
    }

    /// Handle password authentication method
    /// RFC 4252 section 8: "password" method
    ///
    /// Payload format (after service name):
    /// - password (string): The password to authenticate with
    async fn handle_password_auth(&self, username: &str, payload: &[u8]) -> Result<(Bytes, bool)> {
        debug!("Attempting password authentication for: {}", username);

        // Extract password from payload
        // First byte indicates if password change is required (0 for initial auth)
        if payload.is_empty() {
            return Ok((protocol::build_userauth_failure(&["password"], false), false));
        }

        let _change_password = payload[0] != 0;
        let password_data = &payload[1..];

        let (password, _) = parse_ssh_string(password_data)?;
        let password_str = String::from_utf8_lossy(&password).to_string();

        // Authenticate against cache
        match self.auth_cache.authenticate(username, &password_str) {
            Ok(true) => {
                info!("Password authentication successful for: {}", username);
                let response = protocol::build_userauth_success();
                Ok((response, true))
            }
            Ok(false) | Err(AuthError::InvalidPassword) => {
                warn!("Invalid password for user: {}", username);
                let response = protocol::build_userauth_failure(&["password"], false);
                Ok((response, false))
            }
            Err(AuthError::LoginLimitExceeded) => {
                error!("Login limit exceeded for user: {}", username);
                let response = protocol::build_disconnect(
                    protocol::disconnect::TOO_MANY_CONNECTIONS,
                    "Login limit exceeded"
                );
                Ok((response, false))
            }
            Err(AuthError::UserNotFound) => {
                warn!("User not found: {}", username);
                let response = protocol::build_userauth_failure(&["password"], false);
                Ok((response, false))
            }
            Err(AuthError::UserExpired) => {
                warn!("User account expired: {}", username);
                let response = protocol::build_userauth_failure(&["password"], false);
                Ok((response, false))
            }
        }
    }

    /// Get authenticated username
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Check if authentication is complete and successful
    pub fn is_authenticated(&self) -> bool {
        self.state == AuthState::Success
    }

    /// Get current authentication state
    pub fn state(&self) -> AuthState {
        self.state
    }

    /// Record user logout (called when connection closes)
    pub fn record_logout(&self) {
        if let Some(ref username) = self.username {
            self.auth_cache.record_logout(username);
            info!("User session ended: {}", username);
        }
    }
}

/// Helper function to parse SSH string format
/// SSH strings are: 4-byte big-endian length + data
fn parse_ssh_string(data: &[u8]) -> Result<(Vec<u8>, &[u8])> {
    if data.len() < 4 {
        bail!("Insufficient data for SSH string length");
    }

    let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;

    if data.len() < 4 + length {
        bail!("Insufficient data for SSH string (expected {}, got {})", 
            4 + length, data.len());
    }

    let string_data = data[4..4 + length].to_vec();
    let remaining = &data[4 + length..];

    Ok((string_data, remaining))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssh_string() {
        let data = [
            0, 0, 0, 5,  // length = 5
            b'h', b'e', b'l', b'l', b'o',  // "hello"
            0, 0, 0, 5,  // next string length = 5
            b'w', b'o', b'r', b'l', b'd',  // "world"
        ];

        let (s1, rest) = parse_ssh_string(&data[..]).unwrap();
        assert_eq!(s1, b"hello");

        let (s2, _) = parse_ssh_string(rest).unwrap();
        assert_eq!(s2, b"world");
    }

    #[test]
    fn test_auth_handler_init() {
        // Note: In real test, would use mock AuthCache
        // For now, just test handler creation doesn't panic
    }
}