/// Supported KEX algorithms (in preference order)
pub const SUPPORTED_KEX: &[&str] = &[
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1",
];

/// Supported encryption algorithms
pub const SUPPORTED_ENCRYPTION: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes256-ctr",
    "aes128-ctr",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
];

/// Supported MAC algorithms
pub const SUPPORTED_MAC: &[&str] = &[
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha1",
];

/// Supported compression
pub const SUPPORTED_COMPRESSION: &[&str] = &["none"];

/// Key exchange method
#[derive(Debug, Clone, Copy)]
pub enum KexMethod {
    Curve25519,
    DiffieHellmanGroup14Sha256,
    DiffieHellmanGroup14Sha1,
    DiffieHellmanGroup1Sha1,
}

impl KexMethod {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "curve25519-sha256" | "curve25519-sha256@libssh.org" => Some(Self::Curve25519),
            "diffie-hellman-group14-sha256" => Some(Self::DiffieHellmanGroup14Sha256),
            "diffie-hellman-group14-sha1" => Some(Self::DiffieHellmanGroup14Sha1),
            "diffie-hellman-group1-sha1" => Some(Self::DiffieHellmanGroup1Sha1),
            _ => None,
        }
    }
}

/// Selected algorithms after negotiation
#[derive(Debug, Clone)]
pub struct NegotiatedAlgorithms {
    pub kex: String,
    pub encryption_c2s: String,
    pub encryption_s2c: String,
    pub mac_c2s: String,
    pub mac_s2c: String,
}
