use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;

use anyhow::Result;
use async_std_resolver::{config, resolver, AsyncStdResolver};
use trust_dns_proto::rr::{Record, RecordType};
use trust_dns_resolver::config::NameServerConfig;
use trust_dns_resolver::config::Protocol;

use crate::hosts::DEFAULT_HOSTS_PATH;
use crate::hosts::{Host, HostsFile};

/// DNSResolver is a Forwarding DNS resolver
#[derive(Clone)]
pub struct DNSResolver {
    #[allow(dead_code)]
    hosts: HashMap<IpAddr, Host>,
    resolver: AsyncStdResolver,
}

impl DNSResolver {
    pub async fn new(nameservers: Vec<SocketAddr>, bypass_hosts: bool) -> Self {
        let mut config = config::ResolverConfig::new();
        let options = config::ResolverOpts::default();

        // use cloudflare as default nameserver
        if nameservers.is_empty() {
            config = config::ResolverConfig::cloudflare();
        }

        for nameserver in nameservers.into_iter() {
            let udp = NameServerConfig::new(nameserver, Protocol::Udp);
            let tcp = NameServerConfig::new(nameserver, Protocol::Tcp);
            config.add_name_server(udp);
            config.add_name_server(tcp);
        }

        let resolver = resolver(config, options)
            .await
            .expect("failed to connect resolver");

        let mut hosts = HashMap::new();

        if !bypass_hosts {
            let hosts_file = HostsFile::load(DEFAULT_HOSTS_PATH);
            for host in hosts_file.hosts.into_iter() {
                hosts.insert(host.ip, host);
            }
        }

        Self { hosts, resolver }
    }

    pub async fn resolve(&self, name: &str, record_type: RecordType) -> Result<Vec<Record>> {
        let lookup = self.resolver.lookup(name, record_type).await?;
        let records: Vec<Record> = lookup.record_iter().cloned().collect();

        Ok(records)
    }

    pub async fn resolve_ip(&self, name: &str) -> Result<Vec<IpAddr>> {
        let response = self.resolver.lookup_ip(name).await?;
        Ok(response.into_iter().filter_map(Some).collect())
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;

    use trust_dns_proto::rr::RecordType;

    use super::DNSResolver;

    #[tokio::test]
    async fn test_resolve() {
        let resolver = DNSResolver::new(vec![], true).await;
        let response = resolver
            .resolve("www.example.com.", RecordType::A)
            .await
            .unwrap();

        assert!(!response.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_ip() {
        let resolver = DNSResolver::new(vec![], true).await;
        let response = resolver.resolve_ip("www.example.com.").await.unwrap();

        for address in response {
            if address.is_ipv4() {
                assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            } else {
                assert_eq!(
                    address,
                    IpAddr::V6(Ipv6Addr::new(
                        0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946
                    ))
                );
            }
        }
    }

    #[test]
    fn test_send() {
        fn test<C: Send>() {}
        test::<DNSResolver>();
    }

    #[test]
    fn test_sync() {
        fn test<C: Sync>() {}
        test::<DNSResolver>();
    }
}
