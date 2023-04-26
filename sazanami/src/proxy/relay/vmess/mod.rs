#![allow(unused)]
mod aead;
mod aead_header;
mod cipher;
mod kdf;

use cipher::*;
pub mod vmess_stream;
use sazanami_proto::socks5::Address;
use uuid::Uuid;

pub const LW_BUFFER_SIZE: usize = 1024;
pub const HW_BUFFER_SIZE: usize = 65_536;
pub const AES_128_GCM_TAG_LEN: usize = 16;

#[derive(Clone)]
pub struct VmessOption {
    pub uuid: Uuid,
    pub alter_id: u16,
    pub addr: Address,
    pub security_num: u8,
    pub is_udp: bool,
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use anyhow::Result;
    use sazanami_proto::socks5::Address;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    use super::vmess_stream::VmessStream;
    use super::VmessOption;

    #[tokio::test]
    async fn test_vmess() -> Result<()> {
        let addr = Address::SocketAddress(SocketAddr::from_str("93.184.216.34:80")?);

        let uuid = uuid::uuid!("a91d1557-c4c3-4c08-a177-2b8b774fd7f3");
        let stream = TcpStream::connect("127.0.0.1:10110").await?;

        let opt = VmessOption {
            uuid,
            alter_id: 0,
            addr,
            // TODO:
            security_num: 0x03,
            is_udp: false,
        };

        let mut v_stream = VmessStream::new(opt, stream);
        v_stream.write_all(
                "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0.1\r\nAccept: */*\r\n\r\n"
                .as_bytes(),
            )
            .await?;
        let mut buf = [0; 1024];

        let n = v_stream.read(&mut buf[..]).await?;
        assert!(n > 0);

        let resp = String::from_utf8_lossy(&buf);
        println!("resp {resp}");

        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));

        Ok(())
    }
}
