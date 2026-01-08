use anyhow::Result;
use tracing::debug;

/// SSH window controller
/// Manages flow control to prevent buffer overflow
pub struct WindowController {
    /// Initial window size
    initial_size: u32,
    /// Current window size
    current_size: u32,
    /// Bytes consumed since last refill
    consumed: u32,
    /// Refill threshold (percentage)
    refill_threshold: u32,
}

impl WindowController {
    pub fn new(initial_size: u32, refill_threshold: u32) -> Self {
        Self {
            initial_size,
            current_size: initial_size,
            consumed: 0,
            refill_threshold,
        }
    }

    /// Get current window size
    #[allow(dead_code)]
    pub fn current_size(&self) -> u32 {
        self.current_size
    }

    /// Check if we have space in window
    pub fn has_space(&self, bytes: u32) -> bool {
        self.current_size >= bytes
    }

    /// Consume window space (data received)
    pub fn consume(&mut self, bytes: u32) -> Result<()> {
        if bytes > self.current_size {
            anyhow::bail!("Window overflow: tried to consume {} but only {} available",
                bytes, self.current_size);
        }

        self.current_size -= bytes;
        self.consumed += bytes;

        Ok(())
    }

    /// Check if window needs refill
    /// Returns Some(amount) if refill needed
    pub fn check_refill(&mut self) -> Option<u32> {
        let threshold = (self.initial_size * self.refill_threshold) / 100;

        if self.current_size <= threshold && self.consumed > 0 {
            let refill_amount = self.consumed;
            self.current_size += refill_amount;
            self.consumed = 0;

            debug!(
                refill_amount = refill_amount,
                new_window = self.current_size,
                "Window refilled"
            );

            Some(refill_amount)
        } else {
            None
        }
    }

    /// Force refill window
    #[allow(dead_code)]
    pub fn force_refill(&mut self) -> u32 {
        if self.consumed > 0 {
            let refill_amount = self.consumed;
            self.current_size += refill_amount;
            self.consumed = 0;
            refill_amount
        } else {
            0
        }
    }

    /// Reset window to initial size
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.current_size = self.initial_size;
        self.consumed = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_controller() {
        let mut wc = WindowController::new(1000, 50);

        assert_eq!(wc.current_size(), 1000);

        wc.consume(600).unwrap();
        assert_eq!(wc.current_size(), 400);

        assert!(wc.check_refill().is_some());
        assert_eq!(wc.current_size(), 1000);
    }

    #[test]
    fn test_window_no_refill_above_threshold() {
        let mut wc = WindowController::new(1000, 50);

        wc.consume(400).unwrap();
        assert_eq!(wc.current_size(), 600);

        assert!(wc.check_refill().is_none());
    }
}