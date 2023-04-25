use std::net::Ipv4Addr;

use anyhow::Result;
pub use smoltcp::wire::Ipv4Address;
pub use smoltcp::wire::Ipv4Cidr;

pub fn parse_cidr_v4(s: String) -> Result<Ipv4Cidr> {
    let segments = s.splitn(2, '/').collect::<Vec<&str>>();
    let addr = segments[0];
    let len = segments[1];
    let addr: Ipv4Addr = addr.parse()?;
    let prefix = len.parse()?;
    if prefix > 32 || prefix == 0 {
        return Err(anyhow::anyhow!("invalid data"));
    }
    Ok(Ipv4Cidr::new(Ipv4Address::from(addr), prefix))
}

#[allow(non_snake_case)]
pub mod Ipv4CidrSerde {
    use serde::{Deserialize, Deserializer};
    use smoltcp::wire::Ipv4Cidr;

    use super::parse_cidr_v4;

    #[allow(dead_code)]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Ipv4Cidr, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let r = parse_cidr_v4(s).map_err(|e| serde::de::Error::custom(e.to_string()))?;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_v4() {
        assert_eq!(
            parse_cidr_v4("192.168.0.1/24".to_string()).unwrap(),
            Ipv4Cidr::new(Ipv4Address::new(192, 168, 0, 1), 24)
        );

        assert_eq!(
            parse_cidr_v4("10.10.0.1/16".to_string()).unwrap(),
            Ipv4Cidr::new(Ipv4Address::new(10, 10, 0, 1), 16)
        );
    }
    #[test]
    fn test_parse_invalid_cidr_v4() {
        assert!(parse_cidr_v4("192.168.0.1/33".to_string()).is_err());
        assert!(parse_cidr_v4("192.168.0.1/0".to_string()).is_err());
    }
}
