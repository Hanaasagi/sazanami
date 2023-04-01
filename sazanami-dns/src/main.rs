mod hosts;
mod server;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use anyhow::Result;
use server::DNSServer;
use server::Resolver;
use trust_dns_proto::rr::Name;
use trust_dns_proto::rr::RData;
use trust_dns_proto::rr::Record;
use trust_dns_proto::rr::RecordType;

struct FakeDNS {}

impl FakeDNS {
    fn new() -> Self {
        Self {}
    }
}

#[async_trait::async_trait]
impl Resolver for FakeDNS {
    async fn resolve(&self, qname: &str, _qtype: RecordType, _recursive: bool) -> Vec<Record> {
        let mut answer = Record::with(Name::parse(qname, None).unwrap(), RecordType::A, 2);
        answer.set_data(Some(RData::A(Ipv4Addr::from_str("93.184.216.34").unwrap())));

        let mut answers: Vec<Record> = vec![];
        answers.push(answer);

        answers
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let fake_dns = FakeDNS {};
    let listen_at = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53);
    let server = DNSServer::new(listen_at, fake_dns);
    server.serve().await?;

    tokio::signal::ctrl_c().await?;

    Ok(())
}
