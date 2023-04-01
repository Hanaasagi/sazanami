use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::thread;

use anyhow::Result;
use sazanami_tun::Packet;
use sazanami_tun::PacketAction;
use sazanami_tun::PacketHandler;
use sazanami_tun::TunDevice;
use smoltcp::wire::Ipv4Cidr;

struct Router {}

impl Router {
    fn new() -> Self {
        Self {}
    }
}

impl PacketHandler for Router {
    fn handle_packet(&self, packet: &mut Packet) -> PacketAction {
        let src_addr = packet.src_addr();
        let dst_addr = packet.dst_addr();
        println!("src: {}, dst {}", src_addr, dst_addr);

        PacketAction::PASS
    }
}

fn main() -> Result<()> {
    let router = Router::new();

    let tun_name = "sazanami-tun".to_string();
    let tun_ip = Ipv4Addr::new(10, 0, 0, 1);
    let tun_cidr = Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0).into(), 16);
    // Create a tunnel
    let tun_device = TunDevice::new(tun_name, tun_ip, tun_cidr, router)?;
    let stop_flag = tun_device.get_stop_flag();

    let t = tun_device.serve_background()?;

    thread::sleep(std::time::Duration::from_millis(1000));

    stop_flag.store(true, Ordering::Relaxed);

    t.join().expect("Failed to join");

    Ok(())
}
