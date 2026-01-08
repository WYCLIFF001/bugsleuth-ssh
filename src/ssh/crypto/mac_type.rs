/// MAC type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MacType {
    None,           // For AEAD ciphers
    HmacSha256,
    HmacSha1,
}

impl MacType {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "none" => Some(Self::None),
            "hmac-sha2-256" => Some(Self::HmacSha256),
            "hmac-sha1" => Some(Self::HmacSha1),
            _ => None,
        }
    }

    pub fn mac_size(&self) -> usize {
        match self {
            Self::None => 0,
            Self::HmacSha256 => 32,
            Self::HmacSha1 => 20,
        }
    }
}
