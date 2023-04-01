use std::net::Ipv4Addr;

use sazanami_proto::{IpAddress, IpProtocol, TcpPacket, UdpPacket};
use sazanami_tun::Packet;
use sazanami_tun::PacketAction;
use sazanami_tun::PacketHandler;
use tracing::trace;

use crate::tun2proxy::session::SessionManager;

const BEGIN_PORT: u16 = 50000;
const END_PORT: u16 = 60000;

macro_rules! route_packet {
    ($packet_ty: tt, $ipv4_packet: expr, $session_manager: expr, $relay_addr: expr, $relay_port: expr) => {{
        let src_addr = $ipv4_packet.src_addr().into();
        let dst_addr = $ipv4_packet.dst_addr().into();
        let mut packet = $packet_ty::new_checked($ipv4_packet.payload_mut()).unwrap();
        let src_port = packet.src_port();
        let dst_port = packet.dst_port();

        if let Some((new_src_addr, new_src_port, new_dst_addr, new_dst_port)) =
            if src_addr == $relay_addr && src_port == $relay_port {
                let session_manager = $session_manager.read();
                session_manager.get_by_port(dst_port).map(|assoc| {
                    (
                        assoc.dst_addr.into(),
                        assoc.dst_port,
                        assoc.src_addr.into(),
                        assoc.src_port,
                    )
                })
            } else {
                let mut session_manager = $session_manager.write();
                let port =
                    session_manager.get_or_create_session(src_addr, src_port, dst_addr, dst_port);
                session_manager.update_activity_for_port(port);
                Some((dst_addr.into(), port, $relay_addr.into(), $relay_port))
            }
        {
            packet.set_src_port(new_src_port);
            packet.set_dst_port(new_dst_port);
            packet.fill_checksum(
                &IpAddress::Ipv4(new_src_addr),
                &IpAddress::Ipv4(new_dst_addr),
            );
            $ipv4_packet.set_src_addr(new_src_addr);
            $ipv4_packet.set_dst_addr(new_dst_addr);

            $ipv4_packet.fill_checksum();

        trace!(
            "route_packet: src_addr={}, src_port={}, dst_addr={}, dst_port={}, relay_addr={}, relay_port={}, new_src_addr={}, new_dst_addr={}",
            src_addr, src_port, dst_addr, dst_port, $relay_addr, $relay_port, new_src_addr, new_dst_addr
        );
            PacketAction::PASS
        } else {
            PacketAction::DROP
        }
    }};
}

pub(crate) struct Router {
    /// Session manager.
    pub session: SessionManager,
    relay_addr: Ipv4Addr,
    relay_port: u16,
}

impl Router {
    pub(crate) fn new(relay_addr: Ipv4Addr, relay_port: u16) -> Router {
        let session = SessionManager::new(BEGIN_PORT, END_PORT);

        Router {
            session,
            relay_addr,
            relay_port,
        }
    }
}

impl PacketHandler for Router {
    fn handle_packet(&self, packet: &mut Packet) -> PacketAction {
        match packet.next_header() {
            IpProtocol::Udp => {
                route_packet!(
                    UdpPacket,
                    packet,
                    self.session.inner,
                    self.relay_addr,
                    self.relay_port
                )
            }
            IpProtocol::Tcp => {
                route_packet!(
                    TcpPacket,
                    packet,
                    self.session.inner,
                    self.relay_addr,
                    self.relay_port
                )
            }
            _ => PacketAction::PASS,
        }
    }
}
