use std::sync::Arc;
use parking_lot::Mutex;
use bytes::{BytesMut, Bytes};

/// Buffer pool for zero-allocation buffer reuse
pub struct BufferPool {
    standard_size: usize,
    high_throughput_size: usize,
    standard_pool: Mutex<Vec<BytesMut>>,
    high_throughput_pool: Mutex<Vec<BytesMut>>,
    max_pool_size: usize,
}

impl BufferPool {
    pub fn new(standard_size: usize, high_throughput_size: usize) -> Arc<Self> {
        Arc::new(Self {
            standard_size,
            high_throughput_size,
            standard_pool: Mutex::new(Vec::new()),
            high_throughput_pool: Mutex::new(Vec::new()),
            max_pool_size: 1024, // Max buffers to keep
        })
    }

    /// Get a buffer for standard mode
    pub fn get_standard(&self) -> PooledBuffer {
        let mut pool = self.standard_pool.lock();

        let buffer = pool.pop().unwrap_or_else(|| {
            BytesMut::with_capacity(self.standard_size)
        });

        PooledBuffer {
            buffer,
            is_high_throughput: false,
        }
    }

    /// Get a buffer for high-throughput mode
    pub fn get_high_throughput(&self) -> PooledBuffer {
        let mut pool = self.high_throughput_pool.lock();

        let buffer = pool.pop().unwrap_or_else(|| {
            BytesMut::with_capacity(self.high_throughput_size)
        });

        PooledBuffer {
            buffer,
            is_high_throughput: true,
        }
    }

    /// Return a buffer to the pool
    pub fn return_buffer(&self, mut buffer: BytesMut, is_high_throughput: bool) {
        buffer.clear();

        let pool = if is_high_throughput {
            &self.high_throughput_pool
        } else {
            &self.standard_pool
        };

        let mut pool = pool.lock();

        if pool.len() < self.max_pool_size {
            pool.push(buffer);
        }
        // Otherwise drop the buffer
    }

}

/// A buffer borrowed from the pool
pub struct PooledBuffer {
    pub(crate) buffer: BytesMut,
    is_high_throughput: bool,
}

impl PooledBuffer {
    pub fn as_mut(&mut self) -> &mut BytesMut {
        &mut self.buffer
    }

    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    pub fn freeze(self) -> Bytes {
        self.buffer.freeze()
    }

    /// Extract the inner BytesMut
    pub fn into_inner(self) -> BytesMut {
        self.buffer
    }
}