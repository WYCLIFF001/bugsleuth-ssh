use std::path::PathBuf;
use std::time::Duration;

/// Global settings for the SSH forwarding engine
#[derive(Debug, Clone)]
pub struct Settings {
    // Database
    pub db_path: PathBuf,

    // Unix Domain Sockets
    pub socket_dir: PathBuf,
    pub admin_socket: String,
    pub traffic_socket_prefix: String,

    // SSH Settings
    pub host_key_path: PathBuf,
    pub banner: String,

    // Connection Limits
    pub max_handshake_bytes: usize,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub target_connect_timeout: Duration, // Timeout for connecting to target TCP servers

    // Buffer Settings
    pub standard_buffer_size: usize,
    pub high_throughput_buffer_size: usize,
    pub throughput_threshold: u64, // bytes/sec to switch to high throughput

    // SSH Window Settings
    pub initial_window_size: u32,
    pub max_packet_size: u32,
    pub window_refill_threshold: u32, // percentage

    // Runtime
    pub worker_threads: Option<usize>, // None = CPU count
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("/var/lib/ssh-forwarder/users.db"),
            socket_dir: PathBuf::from("/var/run/ssh-forwarder"),
            admin_socket: "admin.sock".to_string(),
            traffic_socket_prefix: "traffic".to_string(),
            host_key_path: PathBuf::from("/etc/ssh-forwarder/host_key"),
            banner: "SSH-2.0-SSH_Forwarder_0.1".to_string(),
            max_handshake_bytes: 8192, // 8KB max garbage
            handshake_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            target_connect_timeout: Duration::from_secs(10), // 10 second timeout for target connections
            standard_buffer_size: 16384, // 16KB
            high_throughput_buffer_size: 65536, // 64KB
            throughput_threshold: 1_000_000, // 1MB/s
            initial_window_size: 2_097_152, // 2MB
            max_packet_size: 32768, // 32KB
            window_refill_threshold: 50, // refill at 50%
            worker_threads: None,
        }
    }
}

impl Settings {
    pub fn worker_count(&self) -> usize {
        self.worker_threads.unwrap_or_else(num_cpus::get)
    }

    pub fn traffic_socket_path(&self, worker_id: usize) -> PathBuf {
        self.socket_dir.join(format!("{}-{}.sock", self.traffic_socket_prefix, worker_id))
    }

    pub fn admin_socket_path(&self) -> PathBuf {
        self.socket_dir.join(&self.admin_socket)
    }
}

// Helper to get CPU count
mod num_cpus {
    pub fn get() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }
}