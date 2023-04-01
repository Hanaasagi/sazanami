use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use sazanami_dns::DNSResolver;
use sazanami_dns::Host;
use sazanami_dns::HostsFile;
use sazanami_dns::Resolver;
use sazanami_dns::DEFAULT_HOSTS_PATH;
use sazanami_ip_pool::IPv4Pool as IPPool;
use tokio::sync::RwLock;
use tracing::debug;
use trust_dns_proto::rr::Name;
use trust_dns_proto::rr::RData;
use trust_dns_proto::rr::Record;
use trust_dns_proto::rr::RecordType;

use crate::config::Action;
use crate::config::ProxyRules;
use crate::storage::DomainIPAssociation;

/// Fake DNS Server, response user's DNS request with a fake IP.
pub(crate) struct FakeDNS {
    // {"FQDN", {IP, HOST, ALIASES}}
    hosts: HashMap<String, Host>,
    // DNS expire ttl
    ttl: u32,
    // Current IP
    ip_pool: Arc<RwLock<IPPool>>,
    // Resolver
    resolver: DNSResolver,
    storage: Arc<RwLock<DomainIPAssociation>>,
    rules: ProxyRules,
}

impl FakeDNS {
    pub async fn new(
        nameservers: Vec<SocketAddr>,
        storage: Arc<RwLock<DomainIPAssociation>>,
        ttl: u32,
        ip_pool: Arc<RwLock<IPPool>>,
        rules: ProxyRules,
    ) -> Self {
        let resolver = DNSResolver::new(nameservers, true).await;

        // TODO: refresh
        let file = HostsFile::load(DEFAULT_HOSTS_PATH);
        let mut hosts = HashMap::new();
        for host in file.hosts.into_iter() {
            hosts.insert(host.fqdn.clone(), host);
        }

        Self {
            hosts,
            ttl,
            ip_pool,
            resolver,
            storage,
            rules,
        }
    }

    fn lookup_hosts(&self, qname: &str) -> Option<&Host> {
        self.hosts.get(qname)
    }

    async fn generate_fake_ip(&self) -> Result<Ipv4Addr> {
        self.ip_pool.write().await.allocate_ip()
    }

    async fn reclaim_unused_ips(&self) {
        let mut ip_pool = self.ip_pool.write().await;
        let mut unused_ips = vec![];
        let ips: Vec<Ipv4Addr> = self.ip_pool.write().await.iter_allocated_ip().collect();
        for ip in ips {
            if self.storage.write().await.query_by_ip(&ip).is_some() {
                unused_ips.push(ip);
            }
        }

        for ip in unused_ips.into_iter() {
            self.ip_pool.write().await.release_ip(ip);
            debug!("reclaim unused ip {}", ip);
        }
    }
}

#[async_trait::async_trait]
impl Resolver for FakeDNS {
    async fn resolve(&self, qname: &str, qtype: RecordType, _recursive: bool) -> Vec<Record> {
        debug!("DNS resolve domain: {}, qtype: {}", qname, qtype);
        // forward to upstream
        if qtype != RecordType::A && qtype != RecordType::AAAA {
            let res = self.resolver.resolve(qname, qtype).await;
            return res.unwrap_or(vec![]);
        }

        let mut answer = Record::with(Name::parse(qname, None).unwrap(), RecordType::A, self.ttl);
        let mut answers: Vec<Record> = vec![];

        // Step 1: lookup hosts file
        if let Some(host) = self.lookup_hosts(qname) {
            match host.ip {
                IpAddr::V4(ip) => {
                    answer.set_data(Some(RData::A(ip)));
                }
                IpAddr::V6(_ip) => {
                    // TODO:
                    unimplemented!("IPv6 not supported");
                }
            }
            answers.push(answer);
            return answers;
        }

        // Step 2:
        match self.rules.action_for_domain(Some(qname), None) {
            Some(Action::Direct) => {
                let res = self.resolver.resolve(qname, qtype).await;
                return res.unwrap_or(vec![]);
            }
            Some(Action::Reject) => return answers,
            _ => {}
        }

        // Step 3: fake ip
        let fake_ip = {
            // reuse fake ip
            if let Some(ip) = self.storage.write().await.query_by_domain(qname) {
                ip.to_owned()
            } else {
                if let Ok(ip) = self.generate_fake_ip().await {
                    ip
                } else {
                    // reclaim and retry
                    self.reclaim_unused_ips().await;
                    self.generate_fake_ip().await.unwrap()
                }
            }
        };

        debug!("generate fake ip {} for domain {}", fake_ip, qname);

        self.storage
            .write()
            .await
            .insert(fake_ip, qname.to_string());

        answer.set_data(Some(RData::A(fake_ip)));
        answers.push(answer);

        answers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn test<C: Send>() {}
        test::<FakeDNS>();
    }

    #[test]
    fn test_sync() {
        fn test<C: Sync>() {}
        test::<FakeDNS>();
    }
}
