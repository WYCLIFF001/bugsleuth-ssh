use anyhow::{Result, bail};
use bytes::{Bytes, BytesMut, BufMut};
use tracing::debug;

use super::cipher_state::CipherState;

/// SSH packet codec
pub struct SshPacketCodec {
    encrypt: Option<CipherState>,
    decrypt: Option<CipherState>,
    block_size: usize,
}

impl SshPacketCodec {
    pub fn new() -> Self {
        Self {
            encrypt: None,
            decrypt: None,
            block_size: 8,
        }
    }

    pub fn enable_encryption(
        &mut self,
        enc_c2s: &str,
        enc_s2c: &str,
        mac_c2s: &str,
        mac_s2c: &str,
        key_c2s: &[u8],
        iv_c2s: &[u8],
        mac_key_c2s: &[u8],
        key_s2c: &[u8],
        iv_s2c: &[u8],
        mac_key_s2c: &[u8],
    ) -> Result<()> {
        self.decrypt = Some(CipherState::new(
            enc_c2s,
            mac_c2s,
            key_c2s,
            iv_c2s,
            mac_key_c2s,
        )?);
        self.encrypt = Some(CipherState::new(
            enc_s2c,
            mac_s2c,
            key_s2c,
            iv_s2c,
            mac_key_s2c,
        )?);

        // Update block size based on cipher type
        if let Some(ref _cipher) = self.encrypt {
            // Note: accessing cipher_type would require making it public
            // For now, keeping block_size default
        }

        debug!("Encryption enabled");
        Ok(())
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypt.is_some()
    }

    /// Encode packet
    pub fn encode_packet(&self, msg_type: u8, payload: &[u8]) -> Result<Bytes> {
        let mut packet = BytesMut::new();

        let payload_len = 1 + payload.len();
        let padding_len = self.block_size - ((5 + payload_len) % self.block_size);
        let padding_len = if padding_len < 4 {
            padding_len + self.block_size
        } else {
            padding_len
        };

        let packet_length = (1 + payload_len + padding_len) as u32;
        packet.put_u32(packet_length);
        packet.put_u8(padding_len as u8);
        packet.put_u8(msg_type);
        packet.put_slice(payload);
        packet.put_slice(&vec![0u8; padding_len]);

        let mut result = packet.freeze();

        if let Some(ref cipher) = self.encrypt {
            let length_bytes = result.slice(0..4);
            let to_encrypt = result.slice(4..);
            let encrypted = cipher.encrypt_packet(&to_encrypt)?;

            let mut final_packet =
                BytesMut::with_capacity(length_bytes.len() + encrypted.len());
            final_packet.put(length_bytes);
            final_packet.put(encrypted);
            result = final_packet.freeze();
        }

        Ok(result)
    }

    /// Decode packet
    pub fn decode_packet(&self, data: &[u8]) -> Result<(u8, Bytes)> {
        if data.len() < 5 {
            bail!("Packet too short");
        }

        let packet_length =
            u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + packet_length {
            bail!("Incomplete packet");
        }

        let packet_data = &data[4..4 + packet_length];

        let plaintext = if let Some(ref cipher) = self.decrypt {
            cipher.decrypt_packet(packet_data)?
        } else {
            Bytes::copy_from_slice(packet_data)
        };

        if plaintext.is_empty() {
            bail!("Empty packet");
        }

        let padding_len = plaintext[0] as usize;
        let msg_type = plaintext[1];
        let payload_end = plaintext.len() - padding_len;

        if payload_end < 2 {
            bail!("Invalid padding");
        }

        let payload = plaintext.slice(2..payload_end);
        Ok((msg_type, payload))
    }
}