use std::path::PathBuf;
use std::str::FromStr;
use std::{error, fmt};
use std::{fmt::Debug, net::SocketAddr};

use bytes::Bytes;
use sazanami_proto::socks5::Address;
use serde;
use serde::Deserialize;
use shadowsocks_crypto::CipherKind;
use url::Url;

// /// Server address
// #[derive(Clone, Debug, Deserialize)]
// #[serde(untagged)]
// pub enum DnsServerAddr {
//     /// IP Address
//     UdpSocketAddr(SocketAddr),
//     /// eg. tcp://114.114.114.114:53
//     TcpSocketAddr(Url),
// }

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ServerProtocol {
    Http,
    Https,
    Socks5,
    #[serde(rename = "ss")]
    ShadowSocks,
    Raw,
    Tuic,
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

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ShadowsocksConfig {
    name: String,
    server: String,
    port: u16,
    password: Option<String>,
    #[serde(default)]
    #[serde(alias = "cipher", with = "cipher_type")]
    method: Option<CipherKind>,
    #[serde(default)]
    udp: bool,
}
impl ShadowsocksConfig {
    pub fn new(
        name: String,
        server: String,
        port: u16,
        password: Option<String>,
        method: Option<CipherKind>,
        udp: bool,
    ) -> Self {
        Self {
            name,
            server,
            port,
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

    /// Get encryption key
    pub fn key(&self) -> Option<Bytes> {
        unimplemented!()
        // Some(self.method()?.bytes_to_key(self.password()?.as_bytes()))
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

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct RawConfig {
    name: String,
    server: String,
    port: u16,
}

impl RawConfig {
    pub fn new(name: String, server: String, port: u16) -> Self {
        Self { name, server, port }
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
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Socks5Config {
    name: String,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}
impl Socks5Config {
    pub fn new(
        name: String,
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            username,
            password,
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
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct TuicConfig {
    name: String,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    certificates: Vec<String>,
    alpn: Vec<String>,
}
impl TuicConfig {
    pub fn new(
        name: String,
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        certificates: Vec<String>,
        alpn: Vec<String>,
    ) -> Self {
        Self {
            name,
            server,
            port,
            username,
            password,
            certificates,
            alpn,
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

    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Get password
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }
    pub fn certificates(&self) -> Vec<PathBuf> {
        self.certificates.iter().map(|p| p.into()).collect()
    }

    pub fn alpn(&self) -> Vec<String> {
        // TODO:
        vec!["h3".to_string()]
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum ServerConfig {
    Shadowsocks(ShadowsocksConfig),
    Socks5(Socks5Config),
    Tuic(TuicConfig),
    Raw(RawConfig),
}

impl ServerConfig {
    pub fn name(&self) -> &str {
        match self {
            Self::Shadowsocks(cfg) => cfg.name(),
            Self::Socks5(cfg) => cfg.name(),
            Self::Tuic(cfg) => cfg.name(),
            Self::Raw(cfg) => cfg.name(),
        }
    }
    pub fn domain(&self) -> &str {
        match self {
            Self::Shadowsocks(cfg) => cfg.domain(),
            Self::Socks5(cfg) => cfg.domain(),
            Self::Tuic(cfg) => cfg.domain(),
            Self::Raw(cfg) => cfg.domain(),
        }
    }
    pub fn port(&self) -> u16 {
        match self {
            Self::Shadowsocks(cfg) => cfg.port(),
            Self::Socks5(cfg) => cfg.port(),
            Self::Tuic(cfg) => cfg.port(),
            Self::Raw(cfg) => cfg.port(),
        }
    }
    pub fn as_shadowsocks_config(self) -> ShadowsocksConfig {
        match self {
            Self::Shadowsocks(cfg) => cfg,
            _ => unreachable!(""),
        }
    }

    pub fn as_socks5_config(self) -> Socks5Config {
        match self {
            Self::Socks5(cfg) => cfg,
            _ => unreachable!(""),
        }
    }
}

pub mod server_config {
    use serde::{Deserialize, Deserializer};

    use super::cipher_type;
    use super::CipherKind;
    use super::ServerConfig;
    use super::ServerProtocol;
    use super::ShadowsocksConfig;
    use super::Socks5Config;

    #[derive(Clone, Debug, Deserialize, PartialEq)]
    struct AllFields {
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
        #[serde(default)]
        certificates: Vec<String>,
        #[serde(default)]
        alpn: Vec<String>,
    }

    fn deserialize<'de, D>(deserializer: D) -> Result<ServerConfig, D::Error>
    where
        D: Deserializer<'de>,
    {
        let all_fields = AllFields::deserialize(deserializer)?;
        match all_fields.protocol {
            ServerProtocol::Socks5 => Ok(ServerConfig::Socks5(Socks5Config::new(
                all_fields.name,
                all_fields.server,
                all_fields.port,
                all_fields.username,
                all_fields.password,
            ))),
            ServerProtocol::ShadowSocks => Ok(ServerConfig::Shadowsocks(ShadowsocksConfig::new(
                all_fields.name,
                all_fields.server,
                all_fields.port,
                all_fields.password,
                all_fields.method,
                all_fields.udp,
            ))),
            _ => {
                unimplemented!("TODO more server protocol")
            }
        }
    }
}

pub mod server_configs {
    use serde::{Deserialize, Deserializer};

    use super::ServerConfig;

    fn deserialize<'de, D>(deserializer: D) -> Result<Vec<ServerConfig>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let cfgs: Vec<ServerConfig> = Vec::deserialize(deserializer)?;

        Ok(cfgs)
    }
}
