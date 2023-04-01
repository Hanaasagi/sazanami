use std::str::FromStr;
use std::{error, fmt};
use std::{fmt::Debug, net::SocketAddr};

use bytes::Bytes;
use sazanami_proto::socks5::Address;
use serde::Deserialize;
use shadowsocks_crypto::CipherKind;
use url::Url;

/// Server address
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum DnsServerAddr {
    /// IP Address
    UdpSocketAddr(SocketAddr),
    /// eg. tcp://114.114.114.114:53
    TcpSocketAddr(Url),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ServerProtocol {
    Http,
    Https,
    Socks5,
    #[serde(rename = "ss")]
    ShadowSocks,
    Raw,
}

/// Configuration for a server
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct ServerConfig {
    /// Server address
    name: String,
    server: String,
    port: u16,
    #[serde(alias = "type")]
    protocol: ServerProtocol,
    username: Option<String>,
    password: Option<String>,
    #[serde(default)]
    #[serde(alias = "cipher", with = "cipher_type")]
    method: Option<CipherKind>,
    #[serde(default)]
    udp: bool,
}

mod cipher_type {
    use std::str::FromStr;

    use serde::de::Error;
    use serde::{Deserialize, Deserializer};

    use super::CipherKind;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<CipherKind>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            None => Ok(None),
            Some(s) => Ok(Some(CipherKind::from_str(&s).map_err(Error::custom)?)),
        }
    }
}

mod server_addr {
    use std::str::FromStr;

    use serde::de::Error;
    use serde::{Deserialize, Deserializer};

    use super::Address;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Address, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Address::from_str(&s)
            .map_err(|_| Error::custom(format!("invalid value: {s}, ip:port or domain:port")))
    }
}

impl ServerConfig {
    pub fn new(
        name: String,
        server: String,
        port: u16,
        protocol: ServerProtocol,
        username: Option<String>,
        password: Option<String>,
        method: Option<CipherKind>,
        udp: bool,
    ) -> Self {
        Self {
            name,
            server,
            port,
            protocol,
            username,
            password,
            method,
            udp,
        }
    }

    /// Get server name
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn domain(&self) -> &str {
        &self.server
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    // TODO:
    /// Get server address
    pub fn addr(&self) -> Address {
        Address::from_str(&format!("{}:{}", self.server, self.port)).unwrap()
    }

    /// Get server protocol
    pub fn protocol(&self) -> ServerProtocol {
        self.protocol
    }

    /// Get encryption key
    pub fn key(&self) -> Option<Bytes> {
        unimplemented!()
        // Some(self.method()?.bytes_to_key(self.password()?.as_bytes()))
    }

    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Get password
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }
    /// Get method
    pub fn method(&self) -> Option<CipherKind> {
        self.method
    }

    pub fn support_udp(&self) -> bool {
        self.udp
    }
}
