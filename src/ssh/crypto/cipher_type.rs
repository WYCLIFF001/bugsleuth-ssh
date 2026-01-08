/// Cipher type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CipherType {
    ChaCha20Poly1305,
    Aes256Ctr,
    Aes128Ctr,
}

impl CipherType {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "chacha20-poly1305@openssh.com" => Some(Self::ChaCha20Poly1305),
            "aes256-ctr" => Some(Self::Aes256Ctr),
            "aes128-ctr" => Some(Self::Aes128Ctr),
            _ => None,
        }
    }

    pub fn key_size(&self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => 32,
            Self::Aes256Ctr => 32,
            Self::Aes128Ctr => 16,
        }
    }

    pub fn iv_size(&self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => 12,
            Self::Aes256Ctr => 16,
            Self::Aes128Ctr => 16,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => 8,
            Self::Aes256Ctr => 16,
            Self::Aes128Ctr => 16,
        }
    }
}
