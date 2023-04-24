// The following code was modified from https://github.com/hugglesfox/hosts-rs
// Original License:
//
// MIT License
//
// Copyright (c) 2019 Hayden Hughes
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::path::Path;

pub const DEFAULT_HOSTS_PATH: &str = "/etc/hosts";

// impl Hosts {
//     pub fn load() -> Result<Hosts, LoadHostError> {
//         let mut f = File::open(HOSTS_PATH).map_err(|_| LoadHostError::from("open /etc/hosts"))?;
//         let mut content = String::new();
//         let _ = f
//             .read_to_string(&mut content)
//             .map_err(|_| LoadHostError::from("read /etc/hosts"))?;
//         Hosts::parse(&content)
//     }
// }

#[derive(Debug, PartialEq, Clone)]
pub struct Hosts {
    hosts: Vec<Host>,
}

#[macro_export]
macro_rules! aliases {
    ($( $x:expr ), +) => {
        {
            Some(vec!($($x),+))
        }
    };

    () => (None);
}

#[derive(Debug, PartialEq, Clone)]
pub struct Host {
    pub ip: IpAddr,
    pub fqdn: String,
    pub aliases: Option<Vec<String>>,
}

impl Host {
    pub fn new(ip: &str, fqdn: &str, aliases: Option<Vec<&str>>) -> Host {
        Host {
            ip: ip.parse().expect("Invalid ip address"),
            fqdn: fqdn.into(),
            aliases: aliases.map(|v| v.iter().map(|s| s.to_string()).collect()),
        }
    }
}

impl<'a, T: Into<&'a str>> From<T> for Host {
    fn from(s: T) -> Host {
        let values: Vec<&str> = s.into().split_whitespace().collect();
        Host::new(
            values.first().expect("IP not found"),
            values.get(1).expect("FQDN not found"),
            match values.get(2..) {
                Some([]) => None,
                Some(aliases) => Some(aliases.to_vec()),
                _ => None,
            },
        )
    }
}

impl fmt::Display for Host {
    /// Formats the host to output the hosts file standard.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut aliases = String::new();

        if self.aliases.is_some() {
            for alias in self.aliases.as_ref().unwrap() {
                aliases.push_str(alias);
            }
            return write!(f, "{} {} {}", self.ip, self.fqdn, aliases);
        }

        write!(f, "{} {}", self.ip, self.fqdn)
    }
}

pub struct HostsFile {
    pub hosts: Vec<Host>,
}

impl From<&str> for HostsFile {
    /// Parses a hosts file.
    fn from(s: &str) -> HostsFile {
        let mut hosts: Vec<Host> = vec![];

        for line in s.lines() {
            if line.contains('#') || line.is_empty() {
                continue;
            }

            hosts.push(Host::from(line))
        }
        HostsFile { hosts }
    }
}

impl From<Vec<Host>> for HostsFile {
    fn from(hosts: Vec<Host>) -> HostsFile {
        HostsFile { hosts }
    }
}

impl fmt::Display for HostsFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut hosts_file = String::new();

        for host in self.hosts.clone() {
            hosts_file.push_str(&format!("{}\n", host))
        }

        write!(f, "{}", hosts_file)
    }
}

impl HostsFile {
    /// Create empty HostsFile
    pub fn new() -> HostsFile {
        HostsFile { hosts: Vec::new() }
    }

    /// Load hosts from file.
    pub fn load<P: AsRef<Path>>(path: P) -> HostsFile {
        HostsFile::from(
            fs::read_to_string(&path)
                .expect("Invalid file path")
                .as_str(),
        )
    }

    /// Writes hosts to a hosts file.
    pub fn save<P: AsRef<Path>>(self, path: P) {
        fs::write(&path, format!("{}", self)).expect("Invalid path");
    }
}

impl Default for HostsFile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_file() {
        let hosts_str = "127.0.0.1 localhost\n::1 localhost\n127.0.1.1 foxtrot.localdomain foxtrot";

        let hosts_file = HostsFile::from(hosts_str);

        for (i, line) in hosts_str.lines().enumerate() {
            assert_eq!(format!("{}", hosts_file.hosts[i]), line)
        }
    }

    #[test]
    #[should_panic]
    fn test_bad_ip() {
        Host::new("1234.123.1233", "localhost", None);
    }

    #[test]
    fn test_aliases() {
        assert_eq!(aliases!("test"), Some(vec!("test")));
    }

    #[test]
    fn test_from() {
        let host = Host::new("127.0.0.1", "localhost", aliases!("test"));
        assert_eq!(Host::from("127.0.0.1 localhost test"), host);

        let host = Host::new("127.0.0.1", "localhost", aliases!());
        assert_eq!(Host::from("127.0.0.1 localhost"), host)
    }

    #[test]
    fn test_display() {
        let host = Host::new("127.0.0.1", "localhost", aliases!("test"));
        assert_eq!(format!("{}", host), "127.0.0.1 localhost test");

        let host = Host::new("127.0.0.1", "localhost", aliases!());
        assert_eq!(format!("{}", host), "127.0.0.1 localhost");
    }
}
