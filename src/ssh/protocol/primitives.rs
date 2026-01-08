use anyhow::{Result, bail};
use bytes::{Bytes, BytesMut, Buf, BufMut};

/// SSH string format: 4-byte length + data
pub fn read_ssh_string(buf: &mut &[u8]) -> Result<Bytes> {
    if buf.len() < 4 {
        bail!("Buffer too short for SSH string length");
    }

    let len = buf.get_u32() as usize;

    if buf.len() < len {
        bail!("Buffer too short for SSH string data");
    }

    let data = Bytes::copy_from_slice(&buf[..len]);
    buf.advance(len);

    Ok(data)
}

/// Write SSH string format
pub fn write_ssh_string(buf: &mut BytesMut, data: &[u8]) {
    buf.put_u32(data.len() as u32);
    buf.put_slice(data);
}

/// SSH name-list format: comma-separated names
pub fn read_name_list(buf: &mut &[u8]) -> Result<Vec<String>> {
    let data = read_ssh_string(buf)?;
    let list_str = String::from_utf8_lossy(&data);

    Ok(list_str
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect())
}

/// Write name-list format
pub fn write_name_list(buf: &mut BytesMut, names: &[&str]) {
    let joined = names.join(",");
    write_ssh_string(buf, joined.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_string() {
        let mut buf = BytesMut::new();
        write_ssh_string(&mut buf, b"hello");

        let mut data = &buf[..];
        let result = read_ssh_string(&mut data).unwrap();

        assert_eq!(&result[..], b"hello");
    }

    #[test]
    fn test_name_list() {
        let mut buf = BytesMut::new();
        write_name_list(&mut buf, &["aes128", "aes256", "chacha20"]);

        let mut data = &buf[..];
        let result = read_name_list(&mut data).unwrap();

        assert_eq!(result, vec!["aes128", "aes256", "chacha20"]);
    }
}
