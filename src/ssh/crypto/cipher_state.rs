use anyhow::{Result, bail};
use bytes::Bytes;
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::debug;

use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce as ChaChaNonce};
use aes::{Aes256, Aes128};
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::Hmac;
use sha2::Sha256;
use sha1::Sha1;

use super::cipher_type::CipherType;
use super::mac_type::MacType;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

/// Cipher state for one direction
pub struct CipherState {
    cipher_type: CipherType,
    mac_type: MacType,
    sequence: AtomicU32,
    chacha: Option<ChaCha20Poly1305>,
    aes_key: Option<Vec<u8>>,
    aes_iv: Option<Vec<u8>>,
    mac_key: Option<Vec<u8>>,
}

impl CipherState {
    pub fn new(
        cipher_name: &str,
        mac_name: &str,
        key: &[u8],
        iv: &[u8],
        mac_key: &[u8],
    ) -> Result<Self> {
        let cipher_type = CipherType::from_name(cipher_name)
            .ok_or_else(|| anyhow::anyhow!("Unsupported cipher: {}", cipher_name))?;

        let mac_type = MacType::from_name(mac_name)
            .ok_or_else(|| anyhow::anyhow!("Unsupported MAC: {}", mac_name))?;

        let mut state = Self {
            cipher_type,
            mac_type,
            sequence: AtomicU32::new(0),
            chacha: None,
            aes_key: None,
            aes_iv: None,
            mac_key: None,
        };

        match cipher_type {
            CipherType::ChaCha20Poly1305 => {
                if key.len() < 32 {
                    bail!("Invalid key size for ChaCha20");
                }
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&key[..32]);
                state.chacha = Some(ChaCha20Poly1305::new(&key_array.into()));
            }
            CipherType::Aes256Ctr | CipherType::Aes128Ctr => {
                state.aes_key = Some(key.to_vec());
                state.aes_iv = Some(iv.to_vec());
                if mac_type != MacType::None {
                    state.mac_key = Some(mac_key.to_vec());
                }
            }
        }

        debug!("Created cipher state: {:?} with MAC: {:?}", cipher_type, mac_type);
        Ok(state)
    }

    /// Encrypt SSH packet
    pub fn encrypt_packet(&self, plaintext: &[u8]) -> Result<Bytes> {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);

        match self.cipher_type {
            CipherType::ChaCha20Poly1305 => self.encrypt_chacha(plaintext, seq),
            CipherType::Aes256Ctr | CipherType::Aes128Ctr => {
                self.encrypt_aes_ctr(plaintext, seq)
            }
        }
    }

    fn encrypt_chacha(&self, plaintext: &[u8], seq: u32) -> Result<Bytes> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[8..12].copy_from_slice(&seq.to_be_bytes());
        let nonce = ChaChaNonce::from(nonce_bytes);

        let ciphertext = self.chacha.as_ref().unwrap()
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("ChaCha20 encryption failed: {}", e))?;

        Ok(Bytes::from(ciphertext))
    }

    fn encrypt_aes_ctr(&self, plaintext: &[u8], seq: u32) -> Result<Bytes> {
        let key = self.aes_key.as_ref().unwrap();
        let iv = self.aes_iv.as_ref().unwrap();

        use aes::cipher::generic_array::GenericArray;

        let mut ciphertext = plaintext.to_vec();

        match self.cipher_type {
            CipherType::Aes256Ctr => {
                if key.len() < 32 {
                    bail!("Invalid AES-256 key size");
                }
                if iv.len() < 16 {
                    bail!("Invalid IV size");
                }
                let key_array = GenericArray::from_slice(&key[..32]);
                let iv_array = GenericArray::from_slice(&iv[..16]);
                let mut cipher = Aes256Ctr::new(key_array, iv_array);
                cipher.apply_keystream(&mut ciphertext);
            }
            CipherType::Aes128Ctr => {
                if key.len() < 16 {
                    bail!("Invalid AES-128 key size");
                }
                if iv.len() < 16 {
                    bail!("Invalid IV size");
                }
                let key_array = GenericArray::from_slice(&key[..16]);
                let iv_array = GenericArray::from_slice(&iv[..16]);
                let mut cipher = Aes128Ctr::new(key_array, iv_array);
                cipher.apply_keystream(&mut ciphertext);
            }
            _ => unreachable!(),
        }

        if self.mac_type != MacType::None {
            let mac = self.compute_mac(seq, plaintext)?;
            ciphertext.extend_from_slice(&mac);
        }

        Ok(Bytes::from(ciphertext))
    }

    /// Decrypt SSH packet
    pub fn decrypt_packet(&self, ciphertext: &[u8]) -> Result<Bytes> {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);

        match self.cipher_type {
            CipherType::ChaCha20Poly1305 => self.decrypt_chacha(ciphertext, seq),
            CipherType::Aes256Ctr | CipherType::Aes128Ctr => {
                self.decrypt_aes_ctr(ciphertext, seq)
            }
        }
    }

    fn decrypt_chacha(&self, ciphertext: &[u8], seq: u32) -> Result<Bytes> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[8..12].copy_from_slice(&seq.to_be_bytes());
        let nonce = ChaChaNonce::from(nonce_bytes);

        let plaintext = self.chacha.as_ref().unwrap()
            .decrypt(&nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("ChaCha20 decryption failed: {}", e))?;

        Ok(Bytes::from(plaintext))
    }

    fn decrypt_aes_ctr(&self, ciphertext: &[u8], seq: u32) -> Result<Bytes> {
        let key = self.aes_key.as_ref().unwrap();
        let iv = self.aes_iv.as_ref().unwrap();

        let (encrypted_data, mac_tag) = if self.mac_type != MacType::None {
            let mac_size = self.mac_type.mac_size();
            if ciphertext.len() < mac_size {
                bail!("Ciphertext too short for MAC");
            }
            let split_point = ciphertext.len() - mac_size;
            (&ciphertext[..split_point], Some(&ciphertext[split_point..]))
        } else {
            (ciphertext, None)
        };

        if let Some(tag) = mac_tag {
            let computed_mac = self.compute_mac(seq, encrypted_data)?;
            if tag != &computed_mac[..] {
                bail!("MAC verification failed");
            }
        }

        use aes::cipher::generic_array::GenericArray;

        let mut plaintext = encrypted_data.to_vec();

        match self.cipher_type {
            CipherType::Aes256Ctr => {
                if key.len() < 32 {
                    bail!("Invalid AES-256 key size");
                }
                if iv.len() < 16 {
                    bail!("Invalid IV size");
                }
                let key_array = GenericArray::from_slice(&key[..32]);
                let iv_array = GenericArray::from_slice(&iv[..16]);
                let mut cipher = Aes256Ctr::new(key_array, iv_array);
                cipher.apply_keystream(&mut plaintext);
            }
            CipherType::Aes128Ctr => {
                if key.len() < 16 {
                    bail!("Invalid AES-128 key size");
                }
                if iv.len() < 16 {
                    bail!("Invalid IV size");
                }
                let key_array = GenericArray::from_slice(&key[..16]);
                let iv_array = GenericArray::from_slice(&iv[..16]);
                let mut cipher = Aes128Ctr::new(key_array, iv_array);
                cipher.apply_keystream(&mut plaintext);
            }
            _ => unreachable!(),
        }

        Ok(Bytes::from(plaintext))
    }

    fn compute_mac(&self, seq: u32, data: &[u8]) -> Result<Vec<u8>> {
        let mac_key = self.mac_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No MAC key"))?;

        match self.mac_type {
            MacType::HmacSha256 => {
                // FIXED: Use KeyInit trait explicitly to disambiguate
                use hmac::Mac;
                let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(mac_key)
                    .map_err(|e| anyhow::anyhow!("HMAC init failed: {}", e))?;
                mac.update(&seq.to_be_bytes());
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            MacType::HmacSha1 => {
                // FIXED: Use KeyInit trait explicitly to disambiguate
                use hmac::Mac;
                let mut mac = <HmacSha1 as hmac::Mac>::new_from_slice(mac_key)
                    .map_err(|e| anyhow::anyhow!("HMAC init failed: {}", e))?;
                mac.update(&seq.to_be_bytes());
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            MacType::None => Ok(Vec::new()),
        }
    }

    pub fn sequence(&self) -> u32 {
        self.sequence.load(Ordering::SeqCst)
    }
}