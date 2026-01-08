use std::time::{Duration, Instant};
use tracing::debug;

/// Buffer mode selection based on throughput
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferMode {
    /// Standard mode: 16KB buffers, low latency
    Standard,
    /// High-throughput mode: 64KB buffers, bulk transfer
    HighThroughput,
}

/// Adaptive buffer manager
/// Automatically switches between 16KB and 64KB buffers based on traffic patterns
pub struct AdaptiveBufferManager {
    current_mode: BufferMode,
    bytes_transferred: u64,
    last_mode_switch: Instant,
    measurement_window: Duration,
    throughput_threshold: u64,
}

impl AdaptiveBufferManager {
    pub fn new(throughput_threshold: u64) -> Self {
        Self {
            current_mode: BufferMode::Standard,
            bytes_transferred: 0,
            last_mode_switch: Instant::now(),
            measurement_window: Duration::from_secs(5), // Check every 5 seconds
            throughput_threshold,
        }
    }

    /// Get current buffer mode
    pub fn current_mode(&self) -> BufferMode {
        self.current_mode
    }

    /// Record bytes transferred (low overhead - just addition)
    pub fn record_transfer(&mut self, bytes: u32) {
        self.bytes_transferred += bytes as u64;
    }

    /// Check if mode should switch (only called every 5 seconds)
    pub fn should_switch_mode(&mut self) -> Option<BufferMode> {
        let elapsed = self.last_mode_switch.elapsed();

        // Only check after measurement window
        if elapsed < self.measurement_window {
            return None;
        }

        // Calculate throughput (bytes per second)
        let throughput = self.bytes_transferred / elapsed.as_secs().max(1);

        let new_mode = if throughput >= self.throughput_threshold {
            BufferMode::HighThroughput
        } else {
            BufferMode::Standard
        };

        if new_mode != self.current_mode {
            debug!(
                old_mode = ?self.current_mode,
                new_mode = ?new_mode,
                throughput = throughput,
                "Buffer mode switching"
            );

            self.current_mode = new_mode;
            self.bytes_transferred = 0;
            self.last_mode_switch = Instant::now();
            Some(new_mode)
        } else {
            // Reset measurement window even if no switch
            self.bytes_transferred = 0;
            self.last_mode_switch = Instant::now();
            None
        }
    }

    /// Get buffer size for current mode
    pub fn buffer_size(&self, standard_size: usize, high_throughput_size: usize) -> usize {
        match self.current_mode {
            BufferMode::Standard => standard_size,
            BufferMode::HighThroughput => high_throughput_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_mode_starts_standard() {
        let mgr = AdaptiveBufferManager::new(1_000_000);
        assert_eq!(mgr.current_mode(), BufferMode::Standard);
    }

    #[test]
    fn test_buffer_size() {
        let mgr = AdaptiveBufferManager::new(1_000_000);
        assert_eq!(mgr.buffer_size(16384, 65536), 16384);
    }
}