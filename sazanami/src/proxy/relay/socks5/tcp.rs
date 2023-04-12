use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use sazanami_proto::socks5::{
    Address, AuthenticationRequest, AuthenticationResponse, Command, HandshakeRequest,
    HandshakeResponse, Reply, TcpRequestHeader, TcpResponseHeader, SOCKS5_AUTH_METHOD_NONE,
    SOCKS5_AUTH_METHOD_PASSWORD,
};
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
use tokio::net::TcpStream;

// Socks5 handshake request packet
// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+

// Socks5 handshake response packet
// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+

#[derive(Debug)]
pub struct Socks5TcpStream {
    stream: TcpStream,
}

impl Socks5TcpStream {
    pub async fn connect(
        mut stream: TcpStream,
        addr: Address,
        auth: Option<(String, String)>,
    ) -> Result<Self> {
        if let Some(auth) = auth {
            // auth.0 username
            // auth.1 password
            Self::handshake_with_auth(&mut stream, auth.0, auth.1).await?;
        } else {
            Self::handshake(&mut stream).await?;
        }
        Self::prepare_request(&mut stream, addr).await?;

        Ok(Socks5TcpStream { stream })
    }

    async fn handshake(mut stream: &mut TcpStream) -> Result<()> {
        let handshake_req = HandshakeRequest::new(vec![SOCKS5_AUTH_METHOD_NONE]);
        handshake_req.write_to(&mut stream).await?;
        let handshake_resp = HandshakeResponse::read_from(&mut stream).await?;
        if handshake_resp.chosen_method != SOCKS5_AUTH_METHOD_NONE {
            return Err(Error::new(ErrorKind::InvalidData, "response methods error"));
        }
        Ok(())
    }

    async fn handshake_with_auth(
        mut stream: &mut TcpStream,
        username: String,
        password: String,
    ) -> Result<()> {
        let handshake_req = HandshakeRequest::new(vec![SOCKS5_AUTH_METHOD_PASSWORD]);
        handshake_req.write_to(&mut stream).await?;
        let handshake_resp = HandshakeResponse::read_from(&mut stream).await?;
        if handshake_resp.chosen_method != SOCKS5_AUTH_METHOD_PASSWORD {
            return Err(Error::new(ErrorKind::InvalidData, "response methods error"));
        }

        // username and password
        let auth_req = AuthenticationRequest::new(username, password);
        auth_req.write_to(&mut stream).await?;
        let auth_resp = AuthenticationResponse::read_from(&mut stream).await?;
        if auth_resp.status != 0 {
            return Err(Error::new(ErrorKind::InvalidData, "response methods error"));
        }

        Ok(())
    }

    async fn prepare_request(mut stream: &mut TcpStream, addr: Address) -> Result<()> {
        let req_header = TcpRequestHeader::new(Command::TcpConnect, addr.clone());
        req_header.write_to(&mut stream).await?;
        let resp_header = TcpResponseHeader::read_from(&mut stream).await?;
        if resp_header.reply != Reply::Succeeded {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("reply error: {:?}", resp_header.reply),
            ));
        }

        Ok(())
    }
}

impl AsyncRead for Socks5TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Socks5TcpStream {
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
    use bytes::BytesMut;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn test_socks5_tcp_no_auth() -> Result<()> {
        let mut stream = Socks5TcpStream::connect(
            TcpStream::connect("127.0.0.1:10080").await?,
            Address::DomainNameAddress("example.com".to_string(), 80),
            None,
        )
        .await?;

        // simulate a http request
        stream
            .write_all(
                "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nUser-Agent: curl/8.0.1\r\n\r\nAccept: */*"
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
