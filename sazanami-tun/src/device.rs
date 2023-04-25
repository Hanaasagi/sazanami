use std::io::Read;
use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

use anyhow::Result;
use log::error;
// use cidr::Ipv4Cidr;
use sazanami_proto::{Ipv4Cidr, Ipv4Packet};
use sazanami_sys::TunConfig;

use crate::TunSocket;

pub type Packet<'a> = Ipv4Packet<&'a mut [u8]>;

pub enum PacketAction {
    PASS,
    DROP,
}

pub trait PacketHandler: std::marker::Send + 'static {
    fn handle_packet(&self, packet: &mut Packet) -> PacketAction;
}

/// TunForwarder is used for forwarding packets from a tun device to proxy endpoint.
pub struct TunDevice<T: PacketHandler> {
    /// Name of the tun device.
    tun_name: String,
    /// Tun socket.
    tun_sock: TunSocket,
    // Tun Ip.
    tun_ip: Ipv4Addr,
    /// Tun CIDR
    tun_cidr: Ipv4Cidr,
    /// Packet handler
    handler: T,
    /// stop flag
    pub stop_flag: Arc<AtomicBool>,
}

impl<T: PacketHandler> TunDevice<T> {
    pub fn new(
        tun_name: String,
        tun_ip: Ipv4Addr,
        tun_cidr: Ipv4Cidr,
        handler: T,
    ) -> Result<TunDevice<T>> {
        let socket = TunSocket::new(&tun_name)?;

        Ok(Self {
            tun_name,
            tun_sock: socket,
            tun_ip,
            tun_cidr,
            handler,
            stop_flag: Arc::new(AtomicBool::new(false)),
        })
    }

    fn setup_tun(&self) -> Result<()> {
        let configer = TunConfig::new(
            self.tun_name.to_string(),
            self.tun_ip.to_string(),
            self.tun_cidr.to_string(),
        );
        configer.setup()?;
        Ok(())
    }

    /// Clone a stop flag used for stop the device
    pub fn get_stop_flag(&self) -> Arc<AtomicBool> {
        self.stop_flag.clone()
    }

    /// Serve
    pub fn serve(mut self) {
        let mut buf = vec![0; 65535];
        loop {
            if self.stop_flag.load(Ordering::Relaxed) {
                break;
            }

            // Blocking IO
            let size = self.tun_sock.read(&mut buf).unwrap();
            if size == 0 {
                error!("tun read return 0, exit now");
                break;
            }

            // TODO: v6?
            let mut ipv4_packet = match Ipv4Packet::new_checked(&mut buf[..size]) {
                Err(e) => {
                    eprint!("tun_nat: new packet error: {:?}", e);
                    continue;
                }
                Ok(p) => p,
            };

            let action = self.handler.handle_packet(&mut ipv4_packet);

            match action {
                PacketAction::PASS => {
                    self.tun_sock.write_all(ipv4_packet.as_ref()).unwrap();
                }

                PacketAction::DROP => {}
            }
        }
    }

    /// Serve in a background thread
    pub fn serve_background(self) -> Result<JoinHandle<()>> {
        self.setup_tun()?;

        let handle = thread::spawn(move || {
            self.serve();
        });

        Ok(handle)
    }
}
