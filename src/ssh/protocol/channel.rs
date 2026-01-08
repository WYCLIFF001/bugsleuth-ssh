use anyhow::Result;
use bytes::{Bytes, BytesMut, BufMut};

use super::primitives::{read_ssh_string, write_ssh_string};

/// SSH channel open request
#[derive(Debug)]
pub struct ChannelOpenRequest {
    pub channel_type: String,
    pub sender_channel: u32,
    pub initial_window: u32,
    pub max_packet_size: u32,
    pub host: Option<String>,
    pub port: Option<u32>,
}

impl ChannelOpenRequest {
    pub fn parse(mut data: &[u8]) -> Result<Self> {
        use bytes::Buf;
        
        let channel_type = String::from_utf8(read_ssh_string(&mut data)?.to_vec())?;
        let sender_channel = data.get_u32();
        let initial_window = data.get_u32();
        let max_packet_size = data.get_u32();

        // For direct-tcpip, parse host and port
        let (host, port) = if channel_type == "direct-tcpip" {
            let host = String::from_utf8(read_ssh_string(&mut data)?.to_vec())?;
            let port = data.get_u32();
            let _originator_ip = read_ssh_string(&mut data)?;
            let _originator_port = data.get_u32();
            (Some(host), Some(port))
        } else {
            (None, None)
        };

        Ok(Self {
            channel_type,
            sender_channel,
            initial_window,
            max_packet_size,
            host,
            port,
        })
    }

    /// Validate if this is a supported channel type
    pub fn is_supported(&self) -> bool {
        self.channel_type == "direct-tcpip"
    }
}

/// Build SSH channel open confirmation
pub fn build_channel_open_confirmation(
    recipient_channel: u32,
    sender_channel: u32,
    initial_window: u32,
    max_packet_size: u32,
) -> Bytes {
    let mut buf = BytesMut::new();
    buf.put_u32(recipient_channel);
    buf.put_u32(sender_channel);
    buf.put_u32(initial_window);
    buf.put_u32(max_packet_size);
    buf.freeze()
}

/// Build SSH channel open failure
pub fn build_channel_open_failure(
    recipient_channel: u32,
    reason_code: u32,
    description: &str,
) -> Bytes {
    let mut buf = BytesMut::new();
    buf.put_u32(recipient_channel);
    buf.put_u32(reason_code);
    write_ssh_string(&mut buf, description.as_bytes());
    write_ssh_string(&mut buf, b""); // language tag
    buf.freeze()
}

/// SSH channel open failure reasons
#[allow(dead_code)]
pub mod open_failure {
    pub const ADMINISTRATIVELY_PROHIBITED: u32 = 1;
    pub const CONNECT_FAILED: u32 = 2;
    pub const UNKNOWN_CHANNEL_TYPE: u32 = 3;
    pub const RESOURCE_SHORTAGE: u32 = 4;
}
