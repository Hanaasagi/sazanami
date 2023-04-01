use anyhow::Result;

use crate::utils::run_cmd;

pub struct TunConfig {
    tun_name: String,
    tun_ip: String,
    cidr: String,
}

impl TunConfig {
    pub fn new(tun_name: String, tun_ip: String, cidr: String) -> Self {
        Self {
            tun_name,
            tun_ip,
            cidr,
        }
    }

    /// Create a tun device from config
    pub fn create(&self) -> Result<()> {
        run_cmd("ip", &["tuntap", "add", "mode", "dev", &self.tun_name])?;

        Ok(())
    }

    /// Setup the tun device
    /// sudo ip addr add 10.0.0.1 dev sazanami-tun
    /// sudo ip link set sazanami-tun up
    /// sudo ip route add 10.0.0.0/16 via 10.0.0.1 dev sazanami-tun
    pub fn setup(&self) -> Result<()> {
        run_cmd("ip", &["addr", "add", &self.tun_ip, "dev", &self.tun_name])?;
        run_cmd("ip", &["link", "set", &self.tun_name, "up"])?;
        run_cmd(
            "ip",
            &[
                "route",
                "add",
                &self.cidr,
                "via",
                &self.tun_ip,
                "dev",
                &self.tun_name,
            ],
        )?;
        Ok(())
    }

    // Delete the tun device
    pub fn delete(&self) -> Result<()> {
        // ip route... will be deleted also when tun device is deleted.
        run_cmd("ip", &["link", "delete", &self.tun_name])?;

        Ok(())
    }
}
