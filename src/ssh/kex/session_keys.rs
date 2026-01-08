/// Derived session keys for both directions
#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub key_client_to_server: Vec<u8>,
    pub iv_client_to_server: Vec<u8>,
    pub mac_client_to_server: Vec<u8>,
    pub key_server_to_client: Vec<u8>,
    pub iv_server_to_client: Vec<u8>,
    pub mac_server_to_client: Vec<u8>,
}

impl SessionKeys {
    pub fn new() -> Self {
        Self {
            key_client_to_server: Vec::new(),
            iv_client_to_server: Vec::new(),
            mac_client_to_server: Vec::new(),
            key_server_to_client: Vec::new(),
            iv_server_to_client: Vec::new(),
            mac_server_to_client: Vec::new(),
        }
    }
}
