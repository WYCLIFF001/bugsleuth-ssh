//! Admin control plane implementation
//!
//! The admin control plane provides a JSON-based API over Unix Domain Sockets (UDS) for
//! operational management of the SSH forwarding engine. It runs in a separate async task
//! spawned from the main runtime.
//!
//! # Features
//! - **UDS Listener**: Listens on `admin.sock` in the configured socket directory for
//!   admin API connections. Uses monoio async runtime for non-blocking I/O.
//! - **JSON API**: All requests and responses are JSON-encoded for easy integration with
//!   external tools and management systems. See AdminRequest and AdminResponse enums.
//! - **Hot Reload**: Supports reloading the auth cache from the database without
//!   restarting the server via the "reload" command. Gracefully handles in-flight
//!   connections during reload.
//! - **Session Management**: Provides commands to list active sessions, disconnect users,
//!   get server statistics, and monitor per-user session counts and limits.
//! - **Health Monitoring**: Exposes uptime, total connections, and per-user quotas for
//!   external monitoring systems.
//!
//! # API Endpoints
//! All endpoints use JSON encoding. Send requests via the admin UDS socket:
//! - `{"command": "sessions"}` - List all active sessions
//! - `{"command": "disconnect", "user": "username"}` - Force disconnect a user
//! - `{"command": "reload"}` - Reload auth cache from database
//! - `{"command": "stats"}` - Get server statistics
//! - `{"command": "user_info", "user": "username"}` - Get user details
//! - `{"command": "cleanup"}` - Remove expired users from cache

pub mod socket;
pub mod api;
pub mod handlers;

pub use socket::AdminSocketListener;