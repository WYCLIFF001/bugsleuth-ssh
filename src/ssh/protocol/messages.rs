use bytes::{Bytes, BytesMut};

use super::primitives::{write_ssh_string, write_name_list};

/// Build userauth success message
pub fn build_userauth_success() -> Bytes {
    Bytes::new() // Empty payload
}

/// Build userauth failure message
pub fn build_userauth_failure(methods: &[&str], partial_success: bool) -> Bytes {
    let mut buf = BytesMut::new();
    write_name_list(&mut buf, methods);
    use bytes::BufMut;
    buf.put_u8(partial_success as u8);
    buf.freeze()
}

/// Build service accept message
pub fn build_service_accept(service: &str) -> Bytes {
    let mut buf = BytesMut::new();
    write_ssh_string(&mut buf, service.as_bytes());
    buf.freeze()
}

/// Build disconnect message
pub fn build_disconnect(reason_code: u32, description: &str) -> Bytes {
    let mut buf = BytesMut::new();
    use bytes::BufMut;
    buf.put_u32(reason_code);
    write_ssh_string(&mut buf, description.as_bytes());
    write_ssh_string(&mut buf, b""); // language tag
    buf.freeze()
}

/// SSH disconnect reason codes
#[allow(dead_code)]
pub mod disconnect {
    pub const HOST_NOT_ALLOWED_TO_CONNECT: u32 = 1;
    pub const PROTOCOL_ERROR: u32 = 2;
    pub const KEY_EXCHANGE_FAILED: u32 = 3;
    pub const RESERVED: u32 = 4;
    pub const MAC_ERROR: u32 = 5;
    pub const COMPRESSION_ERROR: u32 = 6;
    pub const SERVICE_NOT_AVAILABLE: u32 = 7;
    pub const PROTOCOL_VERSION_NOT_SUPPORTED: u32 = 8;
    pub const HOST_KEY_NOT_VERIFIABLE: u32 = 9;
    pub const CONNECTION_LOST: u32 = 10;
    pub const BY_APPLICATION: u32 = 11;
    pub const TOO_MANY_CONNECTIONS: u32 = 12;
    pub const AUTH_CANCELLED_BY_USER: u32 = 13;
    pub const NO_MORE_AUTH_METHODS_AVAILABLE: u32 = 14;
    pub const ILLEGAL_USER_NAME: u32 = 15;
}
