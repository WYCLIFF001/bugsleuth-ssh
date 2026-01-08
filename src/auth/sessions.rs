use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use parking_lot::RwLock;

/// Track active sessions per user
#[derive(Debug)]
pub struct SessionTracker {
    sessions: RwLock<HashMap<String, AtomicU32>>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Check if user can login given their limit
    pub fn can_login(&self, username: &str, max_logins: u32) -> bool {
        let sessions = self.sessions.read();

        if let Some(counter) = sessions.get(username) {
            counter.load(Ordering::Acquire) < max_logins
        } else {
            // No existing sessions
            true
        }
    }

    /// Increment login counter for user
    pub fn increment_login(&self, username: &str) {
        let sessions = self.sessions.read();

        if let Some(counter) = sessions.get(username) {
            counter.fetch_add(1, Ordering::AcqRel);
        } else {
            drop(sessions);
            // Need write lock to insert
            let mut sessions = self.sessions.write();
            sessions.entry(username.to_string())
                .or_insert_with(|| AtomicU32::new(0))
                .fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Decrement login counter for user
    /// This MUST be called on disconnect
    pub fn decrement_login(&self, username: &str) {
        let sessions = self.sessions.read();

        if let Some(counter) = sessions.get(username) {
            let prev = counter.fetch_sub(1, Ordering::AcqRel);

            // Sanity check - should never underflow
            if prev == 0 {
                tracing::error!(
                    username = username,
                    "Session counter underflow - this is a bug!"
                );
            }
        } else {
            tracing::warn!(
                username = username,
                "Attempted to decrement non-existent session counter"
            );
        }
    }

    /// Get current active logins for user
    pub fn active_logins(&self, username: &str) -> u32 {
        let sessions = self.sessions.read();
        sessions.get(username)
            .map(|c| c.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    /// Get all active sessions (for admin API)
    pub fn all_sessions(&self) -> Vec<(String, u32)> {
        let sessions = self.sessions.read();
        sessions.iter()
            .map(|(user, counter)| (user.clone(), counter.load(Ordering::Acquire)))
            .filter(|(_, count)| *count > 0)
            .collect()
    }

    /// Force disconnect all sessions for a user
    /// Returns the number of sessions that were active
    pub fn force_disconnect(&self, username: &str) -> u32 {
        let sessions = self.sessions.read();

        if let Some(counter) = sessions.get(username) {
            counter.swap(0, Ordering::AcqRel)
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_tracking() {
        let tracker = SessionTracker::new();

        assert!(tracker.can_login("alice", 2));
        tracker.increment_login("alice");
        assert_eq!(tracker.active_logins("alice"), 1);

        assert!(tracker.can_login("alice", 2));
        tracker.increment_login("alice");
        assert_eq!(tracker.active_logins("alice"), 2);

        assert!(!tracker.can_login("alice", 2));

        tracker.decrement_login("alice");
        assert_eq!(tracker.active_logins("alice"), 1);
        assert!(tracker.can_login("alice", 2));
    }
}