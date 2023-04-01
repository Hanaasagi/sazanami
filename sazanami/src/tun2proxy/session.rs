use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use bitvec::vec::BitVec;
use parking_lot::RwLock;
use tracing::error;

const EXPIRE_SECONDS: u64 = 24 * 60 * 60;

/// ForwardChain is a forwarding chain.
/// (src_addr, src_port) <==> (dst_addr, dst_port)
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForwardChain {
    // Source Address
    pub src_addr: Ipv4Addr,
    // Source Port
    pub src_port: u16,
    // dst Addr
    pub dst_addr: Ipv4Addr,
    // dst Post
    pub dst_port: u16,
    last_activity_ts: u64,
    recycling: bool,
}

impl ForwardChain {
    pub fn new(src_addr: Ipv4Addr, src_port: u16, dst_addr: Ipv4Addr, dst_port: u16) -> Self {
        Self {
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            last_activity_ts: 0,
            recycling: false,
        }
    }
}

impl Hash for ForwardChain {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // only hash src_addr, src_port, dst_addr, dst_port
        self.src_addr.hash(state);
        self.src_port.hash(state);
        self.dst_addr.hash(state);
        self.dst_port.hash(state);
    }
}

#[derive(Clone)]
pub(crate) struct SessionManager {
    pub(crate) inner: Arc<RwLock<InnerSessionManager>>,
}

impl SessionManager {
    pub fn new(begin_port: u16, end_port: u16) -> Self {
        let inner = Arc::new(RwLock::new(InnerSessionManager::new(begin_port, end_port)));
        Self { inner }
    }

    pub fn get_by_port(&self, port: u16) -> Option<(SocketAddr, SocketAddr)> {
        let inner = self.inner.read();
        inner.map.get(&port).map(|assoc| {
            (
                SocketAddr::new(assoc.src_addr.into(), assoc.src_port),
                SocketAddr::new(assoc.dst_addr.into(), assoc.dst_port),
            )
        })
    }

    pub fn update_activity_for_port(&self, port: u16) -> bool {
        self.inner.write().update_activity_for_port(port)
    }

    pub fn recycle_port(&self, port: u16) {
        self.inner.write().recycle_port(port);
    }
}

pub(crate) struct InnerSessionManager {
    map: HashMap<u16, ForwardChain>,
    reverse_map: HashMap<ForwardChain, u16>,
    begin_port: u16,
    next_index: u16,
    available_ports: BitVec,
}

impl InnerSessionManager {
    pub fn new(begin_port: u16, end_port: u16) -> Self {
        let range = (end_port - begin_port) as usize;
        let mut ports = BitVec::with_capacity(range);
        ports.resize(range, true);

        InnerSessionManager {
            map: HashMap::new(),
            reverse_map: HashMap::new(),
            available_ports: ports,
            next_index: 0,
            begin_port,
        }
    }

    fn fetch_next_available_port(&mut self) -> u16 {
        let mut looped = false;
        let index = loop {
            if let Some(i) = self
                .available_ports
                .iter()
                .skip(self.next_index as usize)
                .position(|p| *p)
            {
                break i;
            } else if looped {
                panic!("no available port");
            } else {
                self.next_index = 0;
                looped = true;
            }
        };
        let real_index = self.next_index + index as u16;
        self.available_ports.set(real_index as usize, false);
        self.next_index = real_index + 1;
        real_index + self.begin_port
    }

    pub fn get_by_port(&self, port: u16) -> Option<&ForwardChain> {
        self.map.get(&port)
    }

    pub fn update_activity_for_port(&mut self, port: u16) -> bool {
        if let Some(assoc) = self.map.get_mut(&port) {
            // if `recycling` is true, the port is marked recycle. We shouldn't update activity ts.
            if !assoc.recycling {
                assoc.last_activity_ts = now();
                return true;
            }
        } else {
            error!("update_activity_or_port: port {} not exists", port);
        }
        false
    }

    pub fn recycle_port(&mut self, port: u16) {
        if let Some(assoc) = self.map.get_mut(&port) {
            // we have 30 seconds to clean the connection.
            assoc.last_activity_ts = now() - EXPIRE_SECONDS + 30;
            assoc.recycling = true;
        } else {
            error!("recycle_port: port {} not exists", port);
        }
    }

    pub fn get_or_create_session(
        &mut self,
        src_addr: Ipv4Addr,
        src_port: u16,
        dst_addr: Ipv4Addr,
        dst_port: u16,
    ) -> u16 {
        if let Some(port) = self
            .reverse_map
            .get(&ForwardChain::new(src_addr, src_port, dst_addr, dst_port))
        {
            return *port;
        }

        let port = self.fetch_next_available_port();

        let now = now();
        self.map.insert(
            port,
            ForwardChain {
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                last_activity_ts: now,
                recycling: false,
            },
        );
        self.reverse_map.insert(
            ForwardChain::new(src_addr, src_port, dst_addr, dst_port),
            port,
        );

        let map = &mut self.map;
        let reverse_map = &mut self.reverse_map;
        let available_ports = &mut self.available_ports;
        let begin_port = self.begin_port;
        map.retain(|port, assoc| {
            // when sleeping on Mac m1, subtract with overflow happens.
            let retain = now.wrapping_sub(assoc.last_activity_ts) < EXPIRE_SECONDS;
            if !retain {
                reverse_map.remove(&ForwardChain::new(
                    assoc.src_addr,
                    assoc.src_port,
                    assoc.dst_addr,
                    assoc.dst_port,
                ));
                let idx = *port - begin_port;
                available_ports.set(idx as usize, true);
            }
            retain
        });
        port
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
