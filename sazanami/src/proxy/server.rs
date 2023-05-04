use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use sazanami_dns::DNSResolver;
use sazanami_proto::socks5::Address;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, trace_span, Instrument};

use super::dia_relay::Dialer;
use super::relay::raw::RawTcpStream;
use crate::config::Config;
use crate::io::bridge_stream;
use crate::storage::DomainIPAssociation;
use crate::SessionManager;

/// Local Proxy server, connect to remote relay server
pub(crate) struct ProxyServer {
    /// Listen address
    listen_at: SocketAddr,
    /// Session
    session: SessionManager,
    // DNSResolver
    resolver: DNSResolver,
    /// Use to find domain from src ip
    storage: Arc<RwLock<DomainIPAssociation>>,
    /// Use to dial remote relay server
    dialer: Dialer,
}

impl ProxyServer {
    /// Create a ProxyServer
    pub async fn new(
        listen_at: SocketAddr,
        session: SessionManager,
        storage: Arc<RwLock<DomainIPAssociation>>,
        config: Arc<Config>,
    ) -> Self {
        let resolver = DNSResolver::new(config.dns.upstream.clone(), true).await;
        let dialer = Dialer::new(config).await;
        Self {
            listen_at,
            session,
            resolver,
            storage,
            dialer,
        }
    }

    pub fn listen_at(&self) -> SocketAddr {
        self.listen_at
    }

    async fn get_domain_from_storage(&self, ip: IpAddr) -> Result<String> {
        let domain = match ip {
            IpAddr::V4(ip) => {
                if let Some(v) = self.storage.read().await.query_by_ip(&ip) {
                    v.to_owned()
                } else {
                    return Err(anyhow!("ip is not found in session"));
                }
            }
            IpAddr::V6(_) => {
                return Err(anyhow!("only support ipv4"));
            }
        };
        Ok(domain)
    }

    /// Process incoming connection
    async fn process_incoming(&self, conn: TcpStream) -> Result<()> {
        // peer_addr and peer_port is the tunnel ip address/port
        let peer_addr = conn.peer_addr()?;
        let peer_port = peer_addr.port();

        // User searches domain
        // In DNS, we generate a fake ip for domain
        // User connects the fake ip which is a tunnel ip
        // In tunnel, we forward the ip packet to this proxy
        let (real_src, real_dst) = match self.session.get_by_port(peer_port) {
            Some(s) => s,
            None => {
                return Err(anyhow!("{} is not found in session", peer_port));
            }
        };

        // TODO:
        match real_src.ip() {
            IpAddr::V4(_) => {}
            IpAddr::V6(_) => {
                return Err(anyhow!("only support ipv4"));
            }
        };

        // get domain from ip
        let domain = self.get_domain_from_storage(real_dst.ip()).await?;
        // TODO:
        let domain = domain.trim_end_matches(".").to_string();

        let domain_ips = self.resolver.resolve_ip(&domain).await?;

        // TODO: how to choose a domain has multi ips?
        let domain_ip = domain_ips[0];

        info!(
            "accept new connection src: {}, dst: {}, domain: {}, domain_ip {:?}",
            real_src, real_dst, domain, domain_ip
        );

        let remote_addr = Address::DomainNameAddress(domain, real_dst.port());

        let dialer = self.dialer.clone();
        // TODO:
        let read_timeout = Duration::from_millis(50);
        let write_timeout = Duration::from_millis(50);

        tokio::spawn(async move {
            let stream = RawTcpStream::new(conn);
            let proxy_stream = dialer.connect(remote_addr).await.expect("connect failed");

            // combine two stream
            // TODO: buf size
            bridge_stream(stream, proxy_stream, read_timeout, write_timeout, 4096)
                .await
                .expect("bridge failed");
        });

        Ok(())
    }

    async fn start_local_server(&self) -> Result<()> {
        // listen
        let listener = TcpListener::bind(self.listen_at).await?;

        // Server loop
        loop {
            let (conn, _) = listener.accept().await?;
            let ret = self
                .process_incoming(conn)
                .instrument(trace_span!("server.process"))
                .await;
            if ret.is_err() {
                error!("process connection error: {:?}", ret);
            }
        }
    }

    pub async fn serve(self) -> Result<()> {
        self.start_local_server().await
    }
}
