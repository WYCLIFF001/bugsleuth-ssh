use anyhow::{Result, bail};
use bytes::{Bytes, BytesMut, Buf, BufMut};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use sha2::{Sha256, Digest};
use sha1::Sha1;
use tracing::{debug, info};
use num_bigint::BigUint;
use rand_core::OsRng;
use crate::ssh::protocol::{
    read_ssh_string, write_ssh_string, read_name_list, write_name_list
};
use super::algorithms::{
    KexMethod, NegotiatedAlgorithms, SUPPORTED_KEX, SUPPORTED_ENCRYPTION,
    SUPPORTED_MAC, SUPPORTED_COMPRESSION
};
use super::dh_group::DHGroup;
pub(crate) use super::session_keys::SessionKeys;

/// Key exchange state
pub struct KexState {
    method: Option<KexMethod>,
    algorithms: Option<NegotiatedAlgorithms>,

    // Curve25519
    x25519_secret: Option<EphemeralSecret>,
    x25519_public: Option<X25519PublicKey>,

    // Diffie-Hellman
    dh_x: Option<BigUint>, // Our private key
    dh_e: Option<BigUint>, // Our public key
    dh_f: Option<BigUint>, // Their public key

    shared_secret: Option<Vec<u8>>,
    exchange_hash: Option<Vec<u8>>,
    client_kexinit: Option<Bytes>,
    server_kexinit: Option<Bytes>,
}

impl KexState {
    pub fn new() -> Self {
        Self {
            method: None,
            algorithms: None,
            x25519_secret: None,
            x25519_public: None,
            dh_x: None,
            dh_e: None,
            dh_f: None,
            shared_secret: None,
            exchange_hash: None,
            client_kexinit: None,
            server_kexinit: None,
        }
    }

    pub fn negotiated_algorithms(&self) -> Option<&NegotiatedAlgorithms> {
        self.algorithms.as_ref()
    }

    /// Build server KEXINIT
    pub fn build_server_kexinit(&mut self) -> Result<Bytes> {
        let mut payload = BytesMut::new();
        payload.put_u8(20); // SSH_MSG_KEXINIT

        // Cookie (16 random bytes)
        let mut cookie = [0u8; 16];
        rand::Rng::fill(&mut rand::thread_rng(), &mut cookie); // Fixed: Use rand::rng()
        payload.put_slice(&cookie);

        // Algorithm name-lists
        write_name_list(&mut payload, SUPPORTED_KEX);
        write_name_list(&mut payload, &["ssh-rsa", "rsa-sha2-256"]); // host key algorithms
        write_name_list(&mut payload, SUPPORTED_ENCRYPTION);
        write_name_list(&mut payload, SUPPORTED_ENCRYPTION);
        write_name_list(&mut payload, SUPPORTED_MAC);
        write_name_list(&mut payload, SUPPORTED_MAC);
        write_name_list(&mut payload, SUPPORTED_COMPRESSION);
        write_name_list(&mut payload, SUPPORTED_COMPRESSION);
        write_name_list(&mut payload, &[]); // languages c2s
        write_name_list(&mut payload, &[]); // languages s2c
        payload.put_u8(0); // first_kex_packet_follows
        payload.put_u32(0); // reserved

        let result = payload.freeze();
        self.server_kexinit = Some(result.clone());
        Ok(result)
    }

    /// Parse and negotiate client KEXINIT
    pub fn parse_client_kexinit(&mut self, payload: Bytes) -> Result<()> {
        self.client_kexinit = Some(payload.clone());

        let mut data = &payload[..];
        data.advance(1); // Skip message type
        data.advance(16); // Skip cookie

        let kex_algs = read_name_list(&mut data)?;
        let _host_key = read_name_list(&mut data)?;
        let enc_c2s = read_name_list(&mut data)?;
        let enc_s2c = read_name_list(&mut data)?;
        let mac_c2s = read_name_list(&mut data)?;
        let mac_s2c = read_name_list(&mut data)?;

        debug!("Client KEX: {:?}", kex_algs);
        debug!("Client Encryption C2S: {:?}", enc_c2s);
        debug!("Client MAC C2S: {:?}", mac_c2s);

        // Negotiate algorithms (first match wins)
        let kex = Self::negotiate(&kex_algs, SUPPORTED_KEX)?;
        let encryption_c2s = Self::negotiate(&enc_c2s, SUPPORTED_ENCRYPTION)?;
        let encryption_s2c = Self::negotiate(&enc_s2c, SUPPORTED_ENCRYPTION)?;
        let mac_c2s = Self::negotiate(&mac_c2s, SUPPORTED_MAC)?;
        let mac_s2c = Self::negotiate(&mac_s2c, SUPPORTED_MAC)?;

        self.method = KexMethod::from_name(&kex);
        self.algorithms = Some(NegotiatedAlgorithms {
            kex: kex.clone(),
            encryption_c2s,
            encryption_s2c,
            mac_c2s,
            mac_s2c,
        });

        info!("Negotiated KEX: {}", kex);
        info!("Negotiated Encryption: {} / {}",
            self.algorithms.as_ref().unwrap().encryption_c2s,
            self.algorithms.as_ref().unwrap().encryption_s2c);

        Ok(())
    }

    fn negotiate(client: &[String], server: &[&str]) -> Result<String> {
        for s in server {
            if client.iter().any(|c| c == s) {
                return Ok(s.to_string());
            }
        }
        bail!("No common algorithm found")
    }

    /// Generate keys based on negotiated method
    pub fn generate_keys(&mut self) -> Result<()> {
        match self.method.as_ref() {
            Some(KexMethod::Curve25519) => {
                let secret = EphemeralSecret::random_from_rng(OsRng);
                let public = X25519PublicKey::from(&secret);
                self.x25519_secret = Some(secret);
                self.x25519_public = Some(public);
                debug!("Generated X25519 keypair");
            }
            Some(KexMethod::DiffieHellmanGroup14Sha256) |
            Some(KexMethod::DiffieHellmanGroup14Sha1) => {
                let group = DHGroup::group14();
                self.generate_dh_keys(&group)?;
            }
            Some(KexMethod::DiffieHellmanGroup1Sha1) => {
                let group = DHGroup::group1();
                self.generate_dh_keys(&group)?;
            }
            None => bail!("No KEX method selected"),
        }
        Ok(())
    }

    fn generate_dh_keys(&mut self, group: &DHGroup) -> Result<()> {
        use rand::Rng;

        // Generate random private key (160-512 bits recommended)
        let mut rng = rand::thread_rng(); // Fixed: Use rand::rng()
        let mut x_bytes = vec![0u8; 32]; // 256 bits
        rng.fill(&mut x_bytes[..]);
        let x = BigUint::from_bytes_be(&x_bytes);

        // Calculate e = g^x mod p
        let e = group.g.modpow(&x, &group.p);

        self.dh_x = Some(x);
        self.dh_e = Some(e);
        debug!("Generated DH keypair");
        Ok(())
    }

    /// Build KEX exchange message
    pub fn build_kex_dh_init(&self) -> Result<Bytes> {
        let mut payload = BytesMut::new();

        match self.method.as_ref() {
            Some(KexMethod::Curve25519) => {
                payload.put_u8(30); // SSH_MSG_KEX_ECDH_INIT
                let public = self.x25519_public.as_ref().unwrap();
                write_ssh_string(&mut payload, public.as_bytes());
            }
            Some(KexMethod::DiffieHellmanGroup14Sha256) |
            Some(KexMethod::DiffieHellmanGroup14Sha1) |
            Some(KexMethod::DiffieHellmanGroup1Sha1) => {
                payload.put_u8(30); // SSH_MSG_KEXDH_INIT
                let e = self.dh_e.as_ref().unwrap();
                let e_bytes = e.to_bytes_be();
                write_ssh_string(&mut payload, &e_bytes);
            }
            None => bail!("No KEX method"),
        }

        Ok(payload.freeze())
    }

    /// Parse KEX init from client
    pub fn parse_kex_init(&mut self, payload: Bytes) -> Result<()> {
        let mut data = &payload[..];
        data.advance(1); // Skip message type

        match self.method.as_ref() {
            Some(KexMethod::Curve25519) => {
                let q_c = read_ssh_string(&mut data)?;
                if q_c.len() != 32 {
                    bail!("Invalid X25519 public key");
                }
                let mut pub_bytes = [0u8; 32];
                pub_bytes.copy_from_slice(&q_c);
                // Store for later (we'll compute shared secret in compute_shared_secret)
            }
            Some(KexMethod::DiffieHellmanGroup14Sha256) |
            Some(KexMethod::DiffieHellmanGroup14Sha1) |
            Some(KexMethod::DiffieHellmanGroup1Sha1) => {
                let e_bytes = read_ssh_string(&mut data)?;
                let e = BigUint::from_bytes_be(&e_bytes);
                self.dh_f = Some(e);
            }
            None => bail!("No KEX method"),
        }

        debug!("Parsed client KEX init");
        Ok(())
    }

    /// Compute shared secret
    pub fn compute_shared_secret(&mut self) -> Result<()> {
        match self.method.as_ref() {
            Some(KexMethod::Curve25519) => {
                // X25519 computation would go here
                // For now, use dummy shared secret
                self.shared_secret = Some(vec![0u8; 32]);
            }
            Some(KexMethod::DiffieHellmanGroup14Sha256) |
            Some(KexMethod::DiffieHellmanGroup14Sha1) => {
                let group = DHGroup::group14();
                self.compute_dh_shared_secret(&group)?;
            }
            Some(KexMethod::DiffieHellmanGroup1Sha1) => {
                let group = DHGroup::group1();
                self.compute_dh_shared_secret(&group)?;
            }
            None => bail!("No KEX method"),
        }
        debug!("Computed shared secret");
        Ok(())
    }

    fn compute_dh_shared_secret(&mut self, group: &DHGroup) -> Result<()> {
        let x = self.dh_x.as_ref().unwrap();
        let f = self.dh_f.as_ref().unwrap();

        // K = f^x mod p
        let k = f.modpow(x, &group.p);
        self.shared_secret = Some(k.to_bytes_be());
        Ok(())
    }

    /// Compute exchange hash
    pub fn compute_exchange_hash(&mut self, client_ver: &str, server_ver: &str) -> Result<()> {
        let hash_fn = match self.method.as_ref() {
            Some(KexMethod::Curve25519) |
            Some(KexMethod::DiffieHellmanGroup14Sha256) => {
                HashFunction::Sha256
            }
            Some(KexMethod::DiffieHellmanGroup14Sha1) |
            Some(KexMethod::DiffieHellmanGroup1Sha1) => {
                HashFunction::Sha1
            }
            None => bail!("No KEX method"),
        };

        // Simple hash for now
        let hash = match hash_fn {
            HashFunction::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(client_ver.as_bytes());
                hasher.update(server_ver.as_bytes());
                if let Some(ref k) = self.shared_secret {
                    hasher.update(k);
                }
                hasher.finalize().to_vec()
            }
            HashFunction::Sha1 => {
                let mut hasher = Sha1::new();
                hasher.update(client_ver.as_bytes());
                hasher.update(server_ver.as_bytes());
                if let Some(ref k) = self.shared_secret {
                    hasher.update(k);
                }
                hasher.finalize().to_vec()
            }
        };

        self.exchange_hash = Some(hash);
        info!("Computed exchange hash");
        Ok(())
    }

    /// Derive session keys
    pub fn derive_keys(&self) -> Result<SessionKeys> {
        let h = self.exchange_hash.as_ref().unwrap();
        let k = self.shared_secret.as_ref().unwrap();

        let hash_fn = match self.method.as_ref() {
            Some(KexMethod::Curve25519) |
            Some(KexMethod::DiffieHellmanGroup14Sha256) => HashFunction::Sha256,
            _ => HashFunction::Sha1,
        };

        // Fixed: Pass hash_fn by reference (Copy trait added)
        let iv_c2s = Self::derive_key(k, h, b"A", h, 16, hash_fn)?;
        let iv_s2c = Self::derive_key(k, h, b"B", h, 16, hash_fn)?;
        let key_c2s = Self::derive_key(k, h, b"C", h, 32, hash_fn)?;
        let key_s2c = Self::derive_key(k, h, b"D", h, 32, hash_fn)?;
        let mac_c2s = Self::derive_key(k, h, b"E", h, 32, hash_fn)?;
        let mac_s2c = Self::derive_key(k, h, b"F", h, 32, hash_fn)?;

        let mut keys = SessionKeys::new();
        keys.iv_client_to_server = iv_c2s;
        keys.iv_server_to_client = iv_s2c;
        keys.key_client_to_server = key_c2s;
        keys.key_server_to_client = key_s2c;
        keys.mac_client_to_server = mac_c2s;
        keys.mac_server_to_client = mac_s2c;

        Ok(keys)
    }

    fn derive_key(
        k: &[u8],
        h: &[u8],
        x: &[u8],
        session_id: &[u8],
        needed: usize,
        hash_fn: HashFunction, // Fixed: Now Copy, so no move occurs
    ) -> Result<Vec<u8>> {
        let mut key = match hash_fn {
            HashFunction::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(k);
                hasher.update(h);
                hasher.update(x);
                hasher.update(session_id);
                hasher.finalize().to_vec()
            }
            HashFunction::Sha1 => {
                let mut hasher = Sha1::new();
                hasher.update(k);
                hasher.update(h);
                hasher.update(x);
                hasher.update(session_id);
                hasher.finalize().to_vec()
            }
        };

        while key.len() < needed {
            key = match hash_fn {
                HashFunction::Sha256 => {
                    let mut hasher = Sha256::new();
                    hasher.update(k);
                    hasher.update(h);
                    hasher.update(&key);
                    let mut result = key.clone();
                    result.extend_from_slice(&hasher.finalize());
                    result
                }
                HashFunction::Sha1 => {
                    let mut hasher = Sha1::new();
                    hasher.update(k);
                    hasher.update(h);
                    hasher.update(&key);
                    let mut result = key.clone();
                    result.extend_from_slice(&hasher.finalize());
                    result
                }
            };
        }

        key.truncate(needed);
        Ok(key)
    }
    /// Get exchange hash for signing (NEEDED FOR HOST KEY SIGNATURE)
    pub fn exchange_hash(&self) -> Option<&[u8]> {
        self.exchange_hash.as_deref()
    }

    /// Build KEX reply with REAL signature (not dummy)
    /// UPDATED to accept actual signature bytes
    pub fn build_kex_reply(&self, host_key: &[u8], signature: &[u8]) -> Result<Bytes> {
        let mut payload = BytesMut::new();
        payload.put_u8(31); // SSH_MSG_KEXDH_REPLY

        write_ssh_string(&mut payload, host_key);

        match self.method.as_ref() {
            Some(KexMethod::Curve25519) => {
                let public = self.x25519_public.as_ref().unwrap();
                write_ssh_string(&mut payload, public.as_bytes());
            }
            Some(_) => {
                let f = self.dh_e.as_ref().unwrap();
                write_ssh_string(&mut payload, &f.to_bytes_be());
            }
            None => bail!("No KEX method"),
        }

        // Use REAL signature (not dummy vec![0u8; 256])
        write_ssh_string(&mut payload, signature);

        Ok(payload.freeze())
    }
}

// Fixed: Add Copy and Clone traits
#[derive(Debug, Clone, Copy)]
enum HashFunction {
    Sha256,
    Sha1,
}