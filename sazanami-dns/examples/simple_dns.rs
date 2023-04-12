use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use anyhow::Result;
use sazanami_dns::DNSServer;
use sazanami_dns::Resolver;
use tokio;
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
        // construct a dns response
        let mut answer = Record::with(Name::parse(qname, None).unwrap(), RecordType::A, 2);
        answer.set_data(Some(RData::A(Ipv4Addr::from_str("93.184.216.34").unwrap())));

        let mut answers: Vec<Record> = vec![];
        answers.push(answer);

        answers
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let fake_dns = FakeDNS::new();
    let listen_at = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53);
    let server = DNSServer::new(listen_at, fake_dns);

    tokio::select! {
        res = server.serve() => {
            if let Err(err) = res {
                println!("error {:?}", err);
            }

        }
        _ = tokio::signal::ctrl_c() => {

        }
    }

    Ok(())
}
