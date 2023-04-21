#![feature(async_closure)]
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
#[cfg(target_os = "linux")]
use aya::maps::{MapRefMut, SockHash};
#[cfg(target_os = "linux")]
use aya::programs::{SkMsg, SockOps};
#[cfg(target_os = "linux")]
use aya::{include_bytes_aligned, Bpf};
#[cfg(target_os = "linux")]
use aya_log::BpfLogger;
#[cfg(target_os = "linux")]
use sazanami_common::SockHashKey;

use clap::Parser;
use log::{info, warn};
use sazanami_sys::ResolvConfig;
use sazanami_sys::DEFAULT_RESOVLV_CONF_PATH;
use sazanami_tun::TunDevice;
use tokio::signal;
use tokio::sync::RwLock;
use tracing::error;
use tracing_subscriber;

mod api;
mod config;
mod fake_dns;
mod io;
mod metrics;
mod proxy;
mod storage;
mod tun2proxy;
mod utils;
use api::ApiServer;
use config::Config;
use fake_dns::FakeDNS;
use proxy::ProxyServer as LocalProxy;
use sazanami_dns::DNSServer;
use sazanami_ip_pool::IPv4Pool;
use storage::DomainIPAssociation;
use tun2proxy::router::Router;
use tun2proxy::session::SessionManager;

const PROG_NAME: &str = env!("CARGO_BIN_NAME");
const PROG_VERSION: &str = env!("CARGO_PKG_VERSION");
// TODO: to parameterize
const FAKE_IP_TTL: u32 = 2;

// ----------------------
//      cmd line
// ----------------------

/// Sazanami Transparent Proxy
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// config path
    #[arg(short, long, value_name = "FILE_PATH")]
    config: String,
}

// ----------------------
//     server setup
// ----------------------

/// Create Fake DNS Server
async fn create_dns_server(
    config: Arc<Config>,
    storage: Arc<RwLock<DomainIPAssociation>>,
    ip_pool: Arc<RwLock<IPv4Pool>>,
) -> Result<DNSServer<FakeDNS>> {
    // use the `upstream` field as the real-nameservers
    let nameservers = config.dns.upstream.clone();
    let listen_at = config.dns.listen_at.clone();
    let rules = config.rules.clone();

    let dns_server_impl = FakeDNS::new(nameservers, storage, FAKE_IP_TTL, ip_pool, rules).await;

    let server = DNSServer::new(listen_at, dns_server_impl);

    Ok(server)
}

async fn create_tun_forwarder(config: Arc<Config>, router: Router) -> Result<TunDevice<Router>> {
    let tun_name = config.tun.name.clone();
    let tun_ip = config.tun.ip.clone();
    let tun_cidr = config.tun.cidr.clone();
    let forwarder = TunDevice::new(tun_name, tun_ip, tun_cidr, router)?;

    Ok(forwarder)
}

async fn create_local_proxy(
    config: Arc<Config>,
    session: SessionManager,
    storage: Arc<RwLock<DomainIPAssociation>>,
) -> Result<LocalProxy> {
    // TODO: 0.0.0.0
    let listen_at = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), config.port);
    let server = LocalProxy::new(listen_at, session, storage, config.clone()).await;

    Ok(server)
}

async fn create_api_server(config: Arc<Config>) -> Result<ApiServer> {
    let listen_at = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), config.api_port);
    let server = ApiServer::new(listen_at).await;

    Ok(server)
}

async fn serve(config: Arc<Config>) -> Result<()> {
    // setup resolv.conf, add 127.0.0.1 to nameservers
    let resolv_config = ResolvConfig::new(DEFAULT_RESOVLV_CONF_PATH, true);
    resolv_config.update(&vec!["127.0.0.1".into()])?;

    let storage = Arc::new(RwLock::new(DomainIPAssociation::new()));

    let ip_pool = Arc::new(RwLock::new(IPv4Pool::new(
        config.tun.cidr.address().into(),
        config.tun.cidr.broadcast().unwrap().into(),
    )));

    // TODO: use original_dns as resolver
    let dns_server = create_dns_server(config.clone(), storage.clone(), ip_pool.clone()).await?;

    let router = Router::new(config.tun.ip, config.port);
    let session = router.session.clone();
    let tun_forwarder = create_tun_forwarder(config.clone(), router).await?;

    let proxy_server = create_local_proxy(config.clone(), session, storage.clone()).await?;

    let forwarding_task = tokio::task::spawn(async move {
        let s = tun_forwarder.serve_background().unwrap();
        loop {
            // TODO: better way to solve this
            if s.is_finished() {
                s.join().expect("Failed to join thread");
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        }
    });

    let api_server = create_api_server(config.clone()).await?;
    let dns_server_monitor = tokio_metrics::TaskMonitor::new();
    let proxy_server_monitor = tokio_metrics::TaskMonitor::new();

    // release lock in this block
    {
        let mut registry = metrics::get_metrics_registry().lock().await;

        registry.add("dns", dns_server_monitor.clone());
        registry.add("proxy", proxy_server_monitor.clone());
    }

    tokio::select! {
        res = async {
            info!("dns server is listening at {}", dns_server.listen_at());
            dns_server_monitor.instrument(dns_server.serve()).await
        }=> {
            if let Err(err) = res {
                error!(cause = %err, "Failed to start");
            }
        }
        res = async {
            info!("tun device is up, start to forward packet at {}", config.tun.cidr);
            forwarding_task.await
        }=> {
            if let Err(err) = res {
                error!(cause = %err, "Failed to start");
            }
        }
        res = async {
            info!("local proxy is listening at {}", proxy_server.listen_at());
            proxy_server_monitor.instrument(proxy_server.serve()).await
        }
        => {
            if let Err(err) = res {
                error!(cause = %err, "Failed to start");
            }

        }
        res = async {
            info!("api server is listening at {}", api_server.listen_at());
            api_server.serve().await
        }
        => {
            if let Err(err) = res {
                error!(cause = %err, "Failed to start");
            }

        }
    }
    Ok(())
}

// ----------------------
//        main
// ----------------------

#[tokio::main]
async fn main() -> Result<()> {
    // install global collector configured based on RUST_LOG env var.
    tracing_subscriber::fmt::init();

    // install global metrics
    metrics::setup_metrics_registry();

    match std::env::var("RUST_LOG").map(|s| s.to_lowercase()) {
        Ok(s) if s.contains("trace") => {
            warn!("trace-level logs are used for debugging and may leak some personal information");
        }
        _ => {}
    }
    let args = Args::parse();

    let config: Config = Config::load(&args.config)?;
    let config = Arc::new(config);

    info!("{PROG_NAME} version: {PROG_VERSION}, link start");

    tokio::select! {
        res = serve(config) => {
            if let Err(err) = res {
                error!(cause = %err, "Failed to start");
            }
        }
        _ = signal::ctrl_c() => {
            info!("{PROG_NAME} is shutting down.");
        }
    }
    info!("Exiting...");

    Ok(())
}
