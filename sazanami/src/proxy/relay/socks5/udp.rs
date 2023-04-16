use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use bytes::BufMut;
use bytes::BytesMut;
use sazanami_proto::socks5::{
    Address, AuthenticationRequest, AuthenticationResponse, Command, HandshakeRequest,
    HandshakeResponse, Reply, TcpRequestHeader, TcpResponseHeader, UdpAssociateHeader,
    SOCKS5_AUTH_METHOD_NONE, SOCKS5_AUTH_METHOD_PASSWORD,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Debug)]
pub struct Socks5UdpSocket {
    socket: UdpSocket,
    #[allow(dead_code)]
    associate_conn: TcpStream,
}

impl Socks5UdpSocket {
    pub async fn connect(
        socks5_server: SocketAddr,
        auth: Option<(String, String)>,
    ) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let mut stream =
            timeout(Duration::from_secs(1), TcpStream::connect(socks5_server)).await??;
        if let Some(auth) = auth {
            Self::handshake_with_auth(&mut stream, auth.0, auth.1).await?;
        } else {
            Self::handshake(&mut stream).await?;
        }

        let req_header = TcpRequestHeader::new(
            Command::UdpAssociate,
            Address::SocketAddress(socket.local_addr()?),
            // Address::SocketAddress("0.0.0.0:0".parse().expect("never error")),
        );
        req_header.write_to(&mut stream).await?;
        let resp_header = TcpResponseHeader::read_from(&mut stream).await?;
        if resp_header.reply != Reply::Succeeded {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("reply error: {:?}", resp_header.reply),
            ));
        }
        let server_bind_addr = match resp_header.address {
            Address::SocketAddress(addr) => addr,
            Address::DomainNameAddress(..) => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "invalid udp bind addr, domain is not allowed",
                ));
            }
        };

        socket.connect(server_bind_addr).await?;
        Ok(Socks5UdpSocket {
            socket,
            associate_conn: stream,
        })
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

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        let udp_header = UdpAssociateHeader::new(0, Address::SocketAddress(addr));
        let mut buffer = BytesMut::with_capacity(udp_header.serialized_len());
        let mut size = 0;
        udp_header.write_to_buf(&mut buffer);
        size += udp_header.serialized_len();
        buffer.put_slice(buf);
        size += buf.len();
        let send_size = self.socket.send(&buffer[..size]).await?;
        assert_eq!(send_size, size);
        Ok(buf.len())
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut buffer = vec![0; buf.len() + 2 + 1 + 19];
        let size = self.socket.recv(&mut buffer).await?;
        let udp_header = UdpAssociateHeader::read_from(&mut buffer.as_slice()).await?;
        if udp_header.frag != 0 {
            return Err(Error::new(ErrorKind::InvalidData, "frag is not allowed"));
        }
        let udp_header_len = udp_header.serialized_len();
        let addr = udp_header.address;
        buf[..size - udp_header_len].copy_from_slice(&buffer[udp_header_len..size]);
        let socket_addr = match addr {
            Address::SocketAddress(socket_addr) => socket_addr,
            Address::DomainNameAddress(..) => {
                return Err(Error::new(ErrorKind::InvalidData, "invalid addr format"));
            }
        };
        Ok((size - udp_header_len, socket_addr))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[tokio::test]
    async fn test_socks5_udp_no_auth() -> Result<()> {
        let conn = Socks5UdpSocket::connect(SocketAddr::from_str("127.0.0.1:10080").unwrap(), None)
            .await?;
        let remote_addr = SocketAddr::from_str("8.8.8.8:53").unwrap();
        // this is a dns request payload for lookup example.com
        let size = conn
            .send_to(
                    b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
                remote_addr.clone(),
            )
            .await?;

        let mut buf = vec![0; 1500];
        let (size, addr) = conn.recv_from(&mut buf).await?;
        // example.com address is 93.184.216.34
        assert_eq!(buf[size - 4..size], [93, 184, 216, 34]);
        Ok(())
    }

    #[tokio::test]
    async fn test_socks5_udp_auth() -> Result<()> {
        let conn = Socks5UdpSocket::connect(
            SocketAddr::from_str("127.0.0.1:10081").unwrap(),
            Some(("oshinoko".to_string(), "hoshinoai".to_string())),
        )
        .await?;
        let remote_addr = SocketAddr::from_str("8.8.8.8:53").unwrap();
        // this is a dns request payload for lookup example.com
        let size = conn
            .send_to(
                    b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
                remote_addr.clone(),
            )
            .await?;

        let mut buf = vec![0; 1500];
        let (size, addr) = conn.recv_from(&mut buf).await?;
        // example.com address is 93.184.216.34
        assert_eq!(buf[size - 4..size], [93, 184, 216, 34]);
        Ok(())
    }
}
