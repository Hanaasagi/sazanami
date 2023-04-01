use std::net::SocketAddr;

use anyhow::Result;
// use crate::resolver::DNSResolver;
use tokio::net::UdpSocket;
use trust_dns_proto::op::Header;
use trust_dns_proto::op::MessageType;
use trust_dns_proto::rr::Record;
use trust_dns_proto::rr::RecordType;
use trust_dns_server::authority::MessageResponseBuilder;
use trust_dns_server::server::Request;
use trust_dns_server::server::RequestHandler;
use trust_dns_server::server::ResponseHandler;
use trust_dns_server::server::ResponseInfo;
use trust_dns_server::ServerFuture;

#[async_trait::async_trait]
pub trait Resolver: Send + Sync + Unpin + 'static {
    async fn resolve(&self, qname: &str, qtype: RecordType, recursive: bool) -> Vec<Record>;
}

struct InnerDNSServer<T: Resolver> {
    resolve_handler: T,
}

impl<T: Resolver> InnerDNSServer<T> {
    pub fn new(resolve_handler: T) -> Self {
        InnerDNSServer { resolve_handler }
    }

    async fn constuct_response_answers(&self, request: &Request) -> Vec<Record> {
        let qname = request.query().name();
        let qtype = request.query().query_type();
        let answers = self
            .resolve_handler
            .resolve(qname.to_string().as_str(), qtype, false)
            .await;

        answers
    }

    async fn constuct_response_header(&self, request: &Request) -> Header {
        let mut header = request.header().clone();
        // change message type from query to response
        header.set_message_type(MessageType::Response);
        // DNS Flags:
        // authoritative
        // authentic_data
        // checking_disabled
        // recursion_available
        // recursion_desired
        // truncation
        header.set_authentic_data(false);
        header.set_recursion_available(true);
        header.set_recursion_desired(false);

        header
    }
}

// https://docs.rs/trust-dns-server/latest/trust_dns_server/server/trait.RequestHandler.html
#[async_trait::async_trait]
impl<T: Resolver> RequestHandler for InnerDNSServer<T> {
    // -----------------------------------------------------------------
    // REAL DNS MESSAGE
    // ; <<>> DiG 9.18.13 <<>> www.example.com
    // ;; global options: +cmd
    // ;; Got answer:
    // ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20266
    // ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
    //
    // ;; OPT PSEUDOSECTION:
    // ; EDNS: version: 0, flags:; udp: 512
    // ;; QUESTION SECTION:
    // ;www.example.com.		IN	A
    //
    // ;; ANSWER SECTION:
    // www.example.com.	19869	IN	A	93.184.216.34
    //
    // ;; Query time: 43 msec
    // ;; SERVER: 8.8.8.8#53(8.8.8.8) (UDP)
    // ;; WHEN: Tue Apr 04 21:54:24 CST 2023
    // ;; MSG SIZE  rcvd: 60
    // -----------------------------------------------------------------
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        // https://docs.rs/trust-dns-server/latest/trust_dns_server/server/struct.Request.html
        let _domain = request.query().name();
        let _query_type = request.query().query_type();

        let response_builder = MessageResponseBuilder::from_message_request(request);

        // Empty ?
        let name_servers = request.name_servers();
        let soa: Vec<Record> = vec![];
        let additionals = request.additionals();

        let header = self.constuct_response_header(request).await;
        let answers = self.constuct_response_answers(request).await;
        // ) -> MessageResponse<'q, 'a, A::IntoIter, N::IntoIter, S::IntoIter, D::IntoIter>
        let response = response_builder.build(
            header,
            answers.iter(),
            name_servers.iter(),
            soa.iter(),
            additionals.iter(),
        );
        let info = response_handle.send_response(response).await;

        return info.unwrap();
    }
}

/// DNSServer is a rule-based dns server
pub struct DNSServer<T: Resolver> {
    inner: InnerDNSServer<T>,
    listen_at: SocketAddr,
}

impl<T: Resolver> DNSServer<T> {
    /// Creates a new DNSServer
    ///
    /// # Arguments
    ///
    /// * `listen_at` - DNS Server listening address
    /// * `resolve_handle` - custom DNS resolver
    pub fn new(listen_at: SocketAddr, resolve_handler: T) -> Self {
        let inner = InnerDNSServer::new(resolve_handler);
        DNSServer { inner, listen_at }
    }

    pub fn listen_at(&self) -> SocketAddr {
        self.listen_at
    }

    pub async fn serve(self) -> Result<()> {
        let mut server_fut = ServerFuture::new(self.inner);
        let udp_socket = UdpSocket::bind(self.listen_at).await?;

        server_fut.register_socket(udp_socket);
        server_fut.block_until_done().await?;
        Ok(())
    }
}
