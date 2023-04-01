#![allow(unused)]
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// IP domain name association
pub(crate) struct DomainIPAssociation {
    ip2domain: HashMap<Ipv4Addr, String>,
    domain2ip: HashMap<String, Ipv4Addr>,
}

impl DomainIPAssociation {
    pub fn new() -> Self {
        Self {
            ip2domain: HashMap::new(),
            domain2ip: HashMap::new(),
        }
    }
}

impl DomainIPAssociation {
    /// Insert a new IP domain name association
    pub fn insert(&mut self, ip: Ipv4Addr, domain: String) {
        self.ip2domain.insert(ip, domain.clone());
        self.domain2ip.insert(domain.clone(), ip);
    }

    /// Query domain by IP
    pub fn query_by_ip(&self, ip: &Ipv4Addr) -> Option<&String> {
        self.ip2domain.get(&ip)
    }

    /// Query IP by domain
    pub fn query_by_domain(&self, domain: &str) -> Option<&Ipv4Addr> {
        self.domain2ip.get(domain)
    }

    /// Delete a IP domain name association
    pub fn delete_by_ip(&mut self, ip: Ipv4Addr) {
        let domain = self.ip2domain.remove(&ip);
        if let Some(domain) = domain {
            self.domain2ip.remove(&domain);
        }
    }

    /// Delete a IP domain name association
    pub fn delete_by_domain(&mut self, domain: &str) {
        let ip = self.domain2ip.remove(domain);
        if let Some(ip) = ip {
            self.ip2domain.remove(&ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_ip_association() {
        let mut association = DomainIPAssociation::new();
        association.insert(Ipv4Addr::new(127, 0, 0, 1), "example.com".to_string());
        assert_eq!(
            association.query_by_ip(&Ipv4Addr::new(127, 0, 0, 1)),
            Some(&"example.com".to_string())
        );

        association.delete_by_ip(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(association.query_by_ip(&Ipv4Addr::new(127, 0, 0, 1)), None,);
    }
}
