use std::io::Result;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::ready;
use std::task::{Context, Poll};
use std::time::Duration;
use std::time::Instant;

use sazanami_dns::DNSResolver;
use sazanami_proto::socks5::Address;
use shadowsocks_crypto::CipherCategory;
use shadowsocks_crypto::CipherKind;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use super::raw::RawTcpStream;
use super::shadowsocks::bytes_to_key;
use super::shadowsocks::SSTcpStream;
use super::socks5::Socks5TcpStream;
use crate::config::Config;
use crate::config::ServerConfig;
use crate::config::ServerProtocol;

enum ProxyTcpStreamInner {
    Socks5(Socks5TcpStream),
    Shadowsocks(SSTcpStream),
    Raw(RawTcpStream),
}

/// Dialer is used to connect to a remote server.
#[derive(Clone)]
pub struct Dialer {
    relay_servers: Arc<Mutex<Vec<ServerConfig>>>,
    connect_retries: usize,
    connect_timeout: Duration,
    resolver: DNSResolver,
}

impl Dialer {
    /// Create a dialer with the given config.
    pub async fn new(config: Arc<Config>) -> Self {
        let resolver = DNSResolver::new(config.dns.upstream.clone(), true).await;

        let relay_servers = Arc::new(Mutex::new((*config.proxies).clone()));
        let connect_retries = config.connect_retries as usize;
        let connect_timeout = config.connect_timeout;

        Self {
            relay_servers,
            connect_retries,
            connect_timeout,
            resolver,
        }
    }

    /// Select a upstream server
    async fn select_relay_server(&self) -> ServerConfig {
        // TODO: select a server algorithm
        let servers = self.relay_servers.lock().await;
        servers[0].clone()
    }

    /// Select a relay server and connect to it.
    pub async fn connect(&self, remote_addr: Address) -> Result<ProxyTcpStream> {
        // select a upstream server
        let server = self.select_relay_server().await;
        // TODO: handle all ips
        let relay_ip = self.resolver.resolve_ip(server.domain()).await.unwrap()[0];

        // connect upstream server
        let relay_socket = SocketAddr::new(relay_ip, server.port());
        let retry_strategy = ExponentialBackoff::from_millis(10)
            .map(jitter)
            .take(self.connect_retries);
        let stream = Retry::spawn(retry_strategy, || {
            timeout(self.connect_timeout, TcpStream::connect(relay_socket))
        })
        .await??;

        // wrap the connection to a stream
        let stream_inner = match server.protocol() {
            ServerProtocol::Socks5 => {
                let mut auth = None;
                if server.username().is_some() && server.password().is_some() {
                    auth = Some((
                        server.username().unwrap().to_string(),
                        server.password().unwrap().to_string(),
                    ))
                }
                ProxyTcpStreamInner::Socks5(
                    Socks5TcpStream::connect(stream, remote_addr.clone(), auth).await?,
                )
            }
            ServerProtocol::ShadowSocks => {
                let method = server.method().unwrap_or(CipherKind::NONE);
                let bytes = match method.category() {
                    CipherCategory::None => method.iv_len(),
                    CipherCategory::Stream => method.iv_len(),
                    CipherCategory::Aead => method.salt_len(),
                };
                ProxyTcpStreamInner::Shadowsocks(
                    SSTcpStream::connect(
                        stream,
                        remote_addr.clone(),
                        method,
                        bytes_to_key(
                            server.password().unwrap().as_bytes(),
                            method.key_len(),
                            bytes,
                        ),
                    )
                    .await?,
                )
            }
            ServerProtocol::Raw => {
                //
                ProxyTcpStreamInner::Raw(RawTcpStream::new(stream))
            }
            _ => unimplemented!("TODO"),
        };

        Ok(ProxyTcpStream::new(stream_inner, remote_addr))
    }
}

pub struct ProxyTcpStream {
    // id: u64,
    inner: ProxyTcpStreamInner,
    alive: Arc<AtomicBool>,
    remote_addr: Address,
    created_at: Instant,
}

impl ProxyTcpStream {
    fn new(stream: ProxyTcpStreamInner, remote_addr: Address) -> Self {
        Self {
            inner: stream,
            alive: Arc::new(AtomicBool::new(true)),
            remote_addr,
            created_at: Instant::now(),
        }
    }

    pub fn create_at(&self) -> Instant {
        self.created_at
    }

    pub fn remote_addr(&self) -> &Address {
        &self.remote_addr
    }

    fn shutdown(&self) {
        self.alive.store(false, Ordering::SeqCst);
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

impl AsyncRead for ProxyTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let stream = &mut *self;

        if !stream.is_alive() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "ProxyTcpStream not alive",
            )));
        }

        let before = buf.filled().len();
        let ret = ready!(match &mut stream.inner {
            ProxyTcpStreamInner::Socks5(conn) => Pin::new(conn).poll_read(cx, buf),
            ProxyTcpStreamInner::Shadowsocks(conn) => Pin::new(conn).poll_read(cx, buf),
            ProxyTcpStreamInner::Raw(conn) => Pin::new(conn).poll_read(cx, buf),
        });
        let after = buf.filled().len();
        if before == after {
            self.shutdown();
        }

        match ret {
            Ok(_size) => Poll::Ready(Ok(())),
            e => {
                self.shutdown();
                Poll::Ready(e)
            }
        }
    }
}

impl AsyncWrite for ProxyTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        let stream = &mut *self;
        if !stream.is_alive() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "ProxyTcpStream not alive",
            )));
        }
        let ret = ready!(match &mut stream.inner {
            ProxyTcpStreamInner::Socks5(conn) => Pin::new(conn).poll_write(cx, buf),
            ProxyTcpStreamInner::Shadowsocks(conn) => Pin::new(conn).poll_write(cx, buf),
            ProxyTcpStreamInner::Raw(conn) => Pin::new(conn).poll_write(cx, buf),
        });
        match ret {
            Ok(size) => Poll::Ready(Ok(size)),
            err => {
                self.shutdown();
                Poll::Ready(err)
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let stream = &mut *self;
        if !stream.is_alive() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "ProxyTcpStream not alive",
            )));
        }
        let ret = ready!(match &mut stream.inner {
            ProxyTcpStreamInner::Socks5(conn) => Pin::new(conn).poll_flush(cx),
            ProxyTcpStreamInner::Shadowsocks(conn) => Pin::new(conn).poll_flush(cx),
            ProxyTcpStreamInner::Raw(conn) => Pin::new(conn).poll_flush(cx),
        });
        match ret {
            Ok(()) => Poll::Ready(Ok(())),
            err => {
                self.shutdown();
                Poll::Ready(err)
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let stream = &mut *self;
        if !stream.is_alive() {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "ProxyTcpStream not alive",
            )));
        }
        let ret = ready!(match &mut stream.inner {
            ProxyTcpStreamInner::Socks5(conn) => Pin::new(conn).poll_shutdown(cx),
            ProxyTcpStreamInner::Shadowsocks(conn) => Pin::new(conn).poll_shutdown(cx),
            ProxyTcpStreamInner::Raw(conn) => Pin::new(conn).poll_shutdown(cx),
        });
        self.shutdown();
        Poll::Ready(ret)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_dial_relay() {
        // TODO:
    }
}
