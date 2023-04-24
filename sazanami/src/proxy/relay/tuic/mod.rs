mod connection;
mod utils;
use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::task::{Context, Poll};

use connection::Connection as TuicConnection;
use connection::Endpoint;
use sazanami_proto::socks5::Address;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
use tokio::net::TcpStream;
use tokio_util::compat::Compat;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tuic::Address as TuicAddress;
use tuic_quinn::Connect;

pub struct TuicStream {
    stream: Compat<Connect>,
}

impl TuicStream {
    pub async fn connect(addr: Address) -> Result<Self> {
        let target_addr = match addr {
            Address::DomainNameAddress(domain, port) => TuicAddress::DomainAddress(domain, port),
            Address::SocketAddress(addr) => TuicAddress::SocketAddress(addr),
        };

        let conn = TuicConnection::get().await.unwrap();
        let stream = conn.connect(target_addr).await.unwrap();

        Ok(Self {
            stream: stream.compat(),
        })
    }
}

impl AsyncRead for TuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::str::FromStr;

    use anyhow::Result;
    use bytes::BytesMut;
    use sazanami_proto::Ipv4Address;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    use super::Address;
    use super::Endpoint;
    use super::TuicStream;
    use crate::config::ServerProtocol;
    use crate::config::TuicConfig;

    #[tokio::test]
    async fn test_tuic() -> Result<()> {
        let mut cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        cert_path.push("../misc/tuic-cert.pem");
        let cfg = TuicConfig::new(
            "TUIC Test".to_string(),
            "127.0.0.1".to_string(),
            10100,
            Some("4982c463-9cd9-47b0-84a4-8ee54848a746".to_string()),
            Some("asuka".to_string()),
            vec![cert_path.to_str().unwrap().to_owned()],
            vec!["h3".to_string()],
        );

        Endpoint::set_config(cfg)?;

        let relay_addr = Address::from_str("127.0.0.1:10100").unwrap();
        let target_addr = Address::DomainNameAddress("example.com".to_string(), 80);
        let mut stream = TuicStream::connect(target_addr).await?;

        stream
            .write_all(
                "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0.1\r\nAccept: */*\r\n\r\n"
                .as_bytes(),
            )
            .await?;

        let mut resp = BytesMut::with_capacity(2048);
        stream.read_buf(&mut resp).await?;
        let resp_text = String::from_utf8_lossy(&resp).to_string();
        assert!(resp_text.contains("HTTP/1.1 200 OK"));

        Ok(())
    }
}
